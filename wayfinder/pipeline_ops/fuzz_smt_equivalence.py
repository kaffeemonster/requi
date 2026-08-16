import sys
import random
import z3
import pipeline
from pipeline import ArithMode, BitFrobMode, OpType, MASK_RLEN, MASK_2RLEN, RLEN

# Define Z3 helper operations
def zshl(a, n):
    return a << z3.BitVecVal(n, 32)

def zshr(a, n):
    return z3.LShR(a, z3.BitVecVal(n, 32))

# Redefine Z3 models globally so they are easy to use in fuzzing
def model_ternlog(a, b, c, lut):
    res = z3.BitVecVal(0, 32)
    for i in range(RLEN):
        ai = z3.Extract(i, i, a)
        bi = z3.Extract(i, i, b)
        ci = z3.Extract(i, i, c)
        idx = z3.Concat(ai, bi, ci)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, idx)))
        res = res | (z3.ZeroExt(31, bit) << i)
    return res

def model_lsr(s1, s2, s3):
    amt = s3 & 7
    concat = z3.Concat(s1, s2)
    # ISS maskiert mit (MASK_2RLEN >> amt); MASK_2RLEN = 0xFFFFFFFF (32-bit!).
    # z3py '>>' = ASHR -> explizit LShR (kein logischer Shift in Python).
    return z3.Extract(31, 0, z3.LShR(concat, z3.ZeroExt(32, amt))) & z3.LShR(z3.BitVecVal(0xFFFFFFFF, 32), amt)

def model_lsl(s1, s2, s3):
    amt = s3 & 7
    concat = z3.Concat(s1, s2)
    return z3.Extract(31, 0, (concat << z3.ZeroExt(32, amt)) >> 32)

def model_ror(s1, s3):
    amt = s3 & 7
    concat_ror = z3.Concat(s1, s1)
    return z3.Extract(31, 0, z3.LShR(concat_ror, z3.ZeroExt(32, amt)))

def model_rol(s1, s3):
    amt = s3 & 7
    concat_rol = z3.Concat(s1, s1)
    return z3.Extract(31, 0, (concat_rol << z3.ZeroExt(32, amt)) >> 32)

def model_mask(s3):
    return z3.If(s3 != 0, z3.BitVecVal(0xFFFFFFFF, 32), z3.BitVecVal(0, 32))

def model_maskw(s3):
    n = s3 & 0x1F
    return z3.If(n == 0, z3.BitVecVal(0xFFFFFFFF, 32), (z3.BitVecVal(1, 32) << n) - 1)

def model_sext(s1, pos):
    p = pos & 31
    bit = z3.Extract(p, p, s1)
    mask = (z3.BitVecVal(1, 32) << (p + 1)) - 1
    return z3.If(bit == 1, s1 | ~mask, s1 & mask)

def model_lzc(x):
    pos = z3.BitVecVal(0, 32)
    for i in range(0, 32):
        pos = z3.If(z3.Extract(i, i, x) == 1, z3.BitVecVal(i, 32), pos)
    return z3.If(x == 0, z3.BitVecVal(32, 32), z3.BitVecVal(31, 32) - pos)

def model_tzc(x):
    pos = z3.BitVecVal(0, 32)
    for i in range(31, -1, -1):
        pos = z3.If(z3.Extract(i, i, x) == 1, z3.BitVecVal(i, 32), pos)
    return z3.If(x == 0, z3.BitVecVal(32, 32), pos)

def model_popcnt_b(x):
    x = x - ((z3.LShR(x, 1)) & z3.BitVecVal(0x55555555, 32))
    x = (x & z3.BitVecVal(0x33333333, 32)) + ((z3.LShR(x, 2)) & z3.BitVecVal(0x33333333, 32))
    x = (x + (z3.LShR(x, 4))) & z3.BitVecVal(0x0F0F0F0F, 32)
    return x

def model_popcnt_n(x):
    x = x - ((z3.LShR(x, 1)) & z3.BitVecVal(0x55555555, 32))
    x = (x & z3.BitVecVal(0x33333333, 32)) + ((z3.LShR(x, 2)) & z3.BitVecVal(0x33333333, 32))
    return x

def model_bitswap(x, mask, sh):
    sh_amt = sh & 31
    t = (x ^ zshr(x, sh_amt)) & mask
    return (x ^ t ^ zshl(t, sh_amt)) & 0xFFFFFFFF

# Unmodeled in pipeline_smt.py, let's write correct models:
def model_asr(s1, s2, s3):
    # ISS: (concat >> amt) & MASK_RLEN — Python-arith-Shift auf 64-bit concat,
    # low 32 = concat-Bits amt..31+amt (Sign-Fuellung nur in Bits >= 32, rausmaskiert).
    # ACHTUNG: s3 als Python-int (z3.Extract braucht konkrete Indizes).
    amt = s3 & 7
    concat = z3.Concat(s1, s2)
    return z3.Extract(31 + amt, amt, concat)

def model_bitrev8(s1):
    res = z3.BitVecVal(0, 32)
    for lane in range(4):
        for i in range(8):
            bit = z3.Extract(8 * lane + i, 8 * lane + i, s1)
            res = res | (z3.ZeroExt(31, bit) << (8 * lane + (7 - i)))
    return res

def model_parity_b(s1):
    res = z3.BitVecVal(0, 32)
    for lane in range(4):
        b = z3.Extract(8 * lane + 7, 8 * lane, s1)
        p = z3.BitVecVal(0, 1)
        for i in range(8):
            p = p ^ z3.Extract(i, i, b)
        res = res | (z3.ZeroExt(31, p) << (8 * lane))
    return res

def model_parity_w(s1):
    p = z3.BitVecVal(0, 1)
    for i in range(32):
        p = p ^ z3.Extract(i, i, s1)
    return z3.ZeroExt(31, p)

def model_clmul_lo(s1, s2):
    res = z3.BitVecVal(0, 32)
    for lane in range(4):
        a_l = z3.Extract(8 * lane + 7, 8 * lane, s1)
        b_l = z3.Extract(8 * lane + 7, 8 * lane, s2)
        r_l = z3.BitVecVal(0, 32)
        for k in range(8):
            bit = z3.BitVecVal(0, 1)
            for i in range(max(0, k - 7), min(k, 7) + 1):
                bit = bit ^ (z3.Extract(i, i, a_l) & z3.Extract(k - i, k - i, b_l))
            r_l = r_l | (z3.ZeroExt(31, bit) << k)
        res = res | (r_l << (8 * lane))
    return res

def model_clmul_hi(s1, s2):
    res = z3.BitVecVal(0, 32)
    for lane in range(4):
        a_l = z3.Extract(8 * lane + 7, 8 * lane, s1)
        b_l = z3.Extract(8 * lane + 7, 8 * lane, s2)
        r_l = z3.BitVecVal(0, 32)
        for k in range(8, 16):
            bit = z3.BitVecVal(0, 1)
            for i in range(max(0, k - 7), min(k, 7) + 1):
                bit = bit ^ (z3.Extract(i, i, a_l) & z3.Extract(k - i, k - i, b_l))
            r_l = r_l | (z3.ZeroExt(31, bit) << (k - 8))
        res = res | ((r_l & z3.BitVecVal(0xFF, 32)) << (8 * lane))
    return res

def model_poly_red(x, poly_int):
    poly_degree = poly_int.bit_length() - 1
    if poly_degree <= 0:
        return x
    for i in range(RLEN - 1, poly_degree - 1, -1):
        x = z3.If(z3.Extract(i, i, x) == 1,
                  x ^ z3.BitVecVal(poly_int << (i - poly_degree), 32), x)
    return x

def model_bitzip8(s1):
    x = s1 & z3.BitVecVal(0xFF, 32)
    x = (x | (x << 4)) & z3.BitVecVal(0x0F0F, 32)
    x = (x | (x << 2)) & z3.BitVecVal(0x3333, 32)
    x = (x | (x << 1)) & z3.BitVecVal(0x5555, 32)
    return x & z3.BitVecVal(0xFFFF, 32)

def model_bitunzip8(s1):
    x = s1 & z3.BitVecVal(0x5555, 32)
    x = (x | z3.LShR(x, 1)) & z3.BitVecVal(0x3333, 32)
    x = (x | z3.LShR(x, 2)) & z3.BitVecVal(0x0F0F, 32)
    x = (x | z3.LShR(x, 4)) & z3.BitVecVal(0x00FF, 32)
    return x & z3.BitVecVal(0xFF, 32)

M16_ROW_MASKS = [0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8]
def model_gfni(s1, cst):
    x = s1 & z3.BitVecVal(0xFF, 32)
    const = cst & z3.BitVecVal(0xFF, 32)
    res = z3.BitVecVal(0, 32)
    for i in range(8):
        m = z3.BitVecVal(M16_ROW_MASKS[i], 32)
        v = x & m
        p = v ^ z3.LShR(v, 4)
        p = p ^ z3.LShR(p, 2)
        p = p ^ z3.LShR(p, 1)
        p = p & z3.BitVecVal(1, 32)
        p = p ^ (z3.LShR(const, i) & z3.BitVecVal(1, 32))
        res = res | (z3.ZeroExt(31, z3.Extract(0, 0, p)) << i)
    return res

def model_bcdhc(s1, s2):
    x = (s1 & z3.BitVecVal(0x0F0F0F0F, 32)) + (s2 & z3.BitVecVal(0x0F0F0F0F, 32))
    return z3.LShR(x, 4) & z3.BitVecVal(0x01010101, 32)

def model_log2(x):
    return z3.BitVecVal(31, 32) - model_lzc(x)

def model_log10(x):
    r = z3.BitVecVal(0, 32)
    for k in range(1, 10):
        r = z3.If(z3.UGE(x, z3.BitVecVal(10 ** k, 32)),
                  z3.BitVecVal(k, 32), r)
    return r

NIBLKP_TABLE = [0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6,
                0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8]
def model_niblkp(x):
    acc = z3.BitVecVal(0, 32)
    for i in range(16):
        acc = z3.If((x & 0xF) == i, z3.BitVecVal(NIBLKP_TABLE[i], 32), acc)
    return acc & 0xFF

def model_bmator(s1, s2):
    acc = z3.BitVecVal(0, 32)
    for k in range(32):
        if k == 0:
            ror = s2
        else:
            ror = z3.Concat(z3.Extract(k - 1, 0, s2), z3.Extract(31, k, s2))
        acc = z3.If(z3.Extract(k, k, s1) == 1, acc | ror, acc)
    return acc

def model_bmatxor(s1, s2):
    acc = z3.BitVecVal(0, 32)
    for k in range(32):
        if k == 0:
            ror = s2
        else:
            ror = z3.Concat(z3.Extract(k - 1, 0, s2), z3.Extract(31, k, s2))
        acc = z3.If(z3.Extract(k, k, s1) == 1, acc ^ ror, acc)
    return acc

def model_bmat_n(a, b, is_xor):
    res = z3.BitVecVal(0, 32)
    for i in range(8):
        a_nib = z3.Extract(3 + 4 * i, 4 * i, a)
        b_nib = z3.Extract(3 + 4 * i, 4 * i, b)
        b8 = z3.ZeroExt(4, b_nib)
        acc = z3.BitVecVal(0, 8)
        for k in range(4):
            cond = z3.Extract(k, k, a_nib)
            r4 = (z3.LShR(b8, k) | (b8 << (4 - k))) & 0xF
            r4g = z3.If(cond == 1, r4, z3.BitVecVal(0, 8))
            acc = (acc ^ r4g) if is_xor else (acc | r4g)
        nib_out = z3.Extract(3, 0, acc)
        res = res | (z3.ZeroExt(28, nib_out) << z3.BitVecVal(4 * i, 32))
    return res & 0xFFFFFFFF

def model_pext_n(s1, s2):
    res = z3.BitVecVal(0, 32)
    for i in range(8):
        mi = z3.Extract(i, i, s2)
        out = z3.BitVecVal(0, 4)
        for j in range(i):
            out = out + z3.If(z3.Extract(j, j, s2) == 1,
                              z3.BitVecVal(1, 4), z3.BitVecVal(0, 4))
        nib = z3.ZeroExt(28, z3.Extract(4 * i + 3, 4 * i, s1))
        sh = z3.BitVecVal(4, 32) * z3.ZeroExt(28, out)
        res = res | z3.If(mi == 1, nib << sh, z3.BitVecVal(0, 32))
    return res

def model_pdep_n(s1, s2):
    res = z3.BitVecVal(0, 32)
    for i in range(8):
        mi = z3.Extract(i, i, s2)
        src = z3.BitVecVal(0, 4)
        for j in range(i):
            src = src + z3.If(z3.Extract(j, j, s2) == 1,
                              z3.BitVecVal(1, 4), z3.BitVecVal(0, 4))
        sh_src = z3.BitVecVal(4, 32) * z3.ZeroExt(28, src)
        nib = z3.Extract(3, 0, z3.LShR(s1, sh_src))
        res = res | z3.If(mi == 1, z3.ZeroExt(28, nib) << z3.BitVecVal(4 * i, 32), z3.BitVecVal(0, 32))
    return res

def model_shr_sticky(s1, s2, amt):
    concat = z3.Concat(s1, s2)
    res = z3.Extract(31, 0, z3.LShR(concat, z3.ZeroExt(32, amt))) & z3.LShR(z3.BitVecVal(0xFFFFFFFF, 32), amt)
    mask = (z3.BitVecVal(1, 32) << amt) - 1
    sticky = z3.If(amt == 0, z3.BitVecVal(0, 32), s2 & mask)
    return res, sticky

# Permb Models
def model_permb_byte(s1, s2, ctrl, blank_enable=True):
    concat = z3.Concat(s1, s2)
    res = z3.BitVecVal(0, 32)
    for i in range(4):
        cb = (ctrl >> (8 * i)) & 0xFF
        idx = cb & 0x07
        blank = (cb & 0x80) != 0
        if blank_enable and blank:
            val = z3.BitVecVal(0, 8)
        else:
            val = z3.Extract(7 + 8 * idx, 8 * idx, concat)
        res = res | (z3.ZeroExt(24, val) << z3.BitVecVal(8 * i, 32))
    return res

def model_permb_nib(s1, s2, ctrl):
    concat = z3.Concat(s1, s2)
    res = z3.BitVecVal(0, 32)
    for i in range(8):
        idx = (ctrl >> (4 * i)) & 0x0F
        nib = z3.Extract(3 + 4 * idx, 4 * idx, concat)
        res = res | (z3.ZeroExt(28, nib) << z3.BitVecVal(4 * i, 32))
    return res

def model_permb_shift(s1, s2, n, shift_left=False):
    concat = z3.Concat(s1, s2)
    k = (n & 0x1F) >> 3
    res = z3.BitVecVal(0, 32)
    so = z3.BitVecVal(0, 32)
    if not shift_left:
        for i in range(4):
            idx = k + i
            if idx >= 4:
                val = z3.BitVecVal(0, 8)
            else:
                val = z3.Extract(7 + 8 * idx, 8 * idx, concat)
            res = res | (z3.ZeroExt(24, val) << z3.BitVecVal(8 * i, 32))
        # aux = OR der rausgeschobenen Byte-Werte (ISS-Sticky, pipeline.py:284-285)
        for i in range(min(k, 4)):
            val_so = z3.Extract(7 + 8 * i, 8 * i, concat)
            so = so | z3.ZeroExt(24, val_so)
    else:
        for i in range(4):
            idx = i - k
            if idx < 0:
                val = z3.BitVecVal(0, 8)
            else:
                val = z3.Extract(7 + 8 * idx, 8 * idx, concat)
            res = res | (z3.ZeroExt(24, val) << z3.BitVecVal(8 * i, 32))
        # aux = OR der rausgeschobenen Byte-Werte (ISS-Sticky, pipeline.py:291-292)
        for i in range(min(k, 4)):
            val_so = z3.Extract(7 + 8 * (8 - k + i), 8 * (8 - k + i), concat)
            so = so | z3.ZeroExt(24, val_so)
    return res, so

# Arith4 Models
def model_arith4(s1, s2, s3, mode, c_in=z3.BitVecVal(0, 1), inv_1=False, inv_2=False, inv_3=False, unsigned=False):
    a = (z3.BitVecVal(0, 32) - s1) if inv_1 else s1
    b = (z3.BitVecVal(0, 32) - s2) if inv_2 else s2
    c = (z3.BitVecVal(0, 32) - s3) if inv_3 else s3
    if mode == 1:   # ADD
        res = a + b + c
    elif mode == 2:  # ADDC (inv_2=True = SUBB-Integration: Carry-Beitrag als Borrow c-1)
        res = a + b + c + z3.ZeroExt(31, c_in) - (z3.BitVecVal(1, 32) if inv_2 else z3.BitVecVal(0, 32))
    elif mode == 5:  # SATADD: unsigned=True -> USATADD (Unsigned-Sat, 34-bit zero-ext);
        if unsigned:  # 3-Operanden-Summe bis 3*2^32
            full = z3.ZeroExt(2, a) + z3.ZeroExt(2, b) + z3.ZeroExt(2, c)
            res = z3.If(z3.UGT(full, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0xFFFFFFFF, 32), z3.Extract(31, 0, full))
        else:  # signed sat, 34-bit sign-ext: Summe bis +-3*2^31
            full = z3.SignExt(2, a) + z3.SignExt(2, b) + z3.SignExt(2, c)
            # signed-Vergleich via Vorzeichen-Flip + UGT/ULT (z3py kennt kein SGT/SLT)
            f34 = full ^ z3.BitVecVal(0x200000000, 34)
            res = z3.If(z3.UGT(f34, z3.BitVecVal(0x27FFFFFFF, 34)), z3.BitVecVal(0x7FFFFFFF, 32),
                   z3.If(z3.ULT(f34, z3.BitVecVal(0x180000000, 34)), z3.BitVecVal(0x80000000, 32),
                         z3.Extract(31, 0, full)))
    elif mode == 6:   # AVG
        full = z3.ZeroExt(1, a) + z3.ZeroExt(1, b) + z3.ZeroExt(32, z3.Extract(0, 0, c))
        res = z3.Extract(31, 0, z3.LShR(full, 1))
    elif mode == 7:   # ABSADD: |a|+b+c; Vorzeichen = Bit31 (nicht UGE>=0!)
        absa = z3.If(z3.Extract(31, 31, a) == 1, z3.BitVecVal(0, 32) - a, a)
        res = absa + b + c
    elif mode == 10:  # SLT: unsigned=True -> SLTU, sonst signed (Sign-Flip + Unsigned-Borrow)
        if unsigned:
            full = z3.ZeroExt(2, a) + z3.ZeroExt(2, ~s2) + z3.ZeroExt(2, c)
            res = z3.If(z3.UGT(full, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0, 32), z3.BitVecVal(0xFFFFFFFF, 32))
        else:
            ca = a ^ z3.BitVecVal(0x80000000, 32)
            cb = s2 ^ z3.BitVecVal(0x80000000, 32)
            # 34-Bit: 3-Operanden-Summe bis 3*2^32 (33-Bit wuerde >2^33 wrappen)
            t34 = z3.ZeroExt(2, ca) + z3.ZeroExt(2, (~cb) & 0xFFFFFFFF) + z3.ZeroExt(2, c)
            # carry-out = full >= 2^32 (nicht nur Bit32: Bit33 kann gesetzt sein bei 34-Bit)
            res = z3.If(z3.UGT(t34, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0, 32), z3.BitVecVal(0xFFFFFFFF, 32))
    elif mode == 12:  # MFC
        res = z3.ZeroExt(31, c_in)
    elif mode == 13:  # ADDSHIFT1
        res = a + (b << 1)
    elif mode == 14:  # ADDSHIFT2
        res = a + (b << 2)
    else:
        raise ValueError(f"Unknown model_arith4 mode {mode}")
    return res

# Other arith4 models from __main__
def model_padd(s1, s2, lb):
    lm = 0
    gm = 0
    for i in range(32 // lb):
        lm |= ((1 << (lb - 1)) - 1) << (i * lb)
        gm |= 1 << (i * lb)
    lmv = z3.BitVecVal(lm, 32)
    gmv = z3.BitVecVal(gm, 32)
    t = (s1 & lmv) + (s2 & lmv)
    x = s1 ^ s2
    return (t & lmv) | ((((z3.LShR(x, lb - 1) ^ z3.LShR(t, lb - 1)) & gmv) << (lb - 1)))

def model_cmp(s1, s2, lb):
    if lb == 32:
        return z3.If(s1 == s2, z3.BitVecVal(0xFFFFFFFF, 32), z3.BitVecVal(0, 32))
    lm = 0
    gm = 0
    for i in range(32 // lb):
        lm |= ((1 << (lb - 1)) - 1) << (i * lb)
        gm |= 1 << (i * lb)
    lmv = z3.BitVecVal(lm, 32)
    gmv = z3.BitVecVal(gm, 32)
    x = s1 ^ s2
    y = (x & lmv) + lmv
    z = (~(y | x | lmv)) & 0xFFFFFFFF
    m = (z3.LShR(z, lb - 1)) & gmv
    return ((m << lb) - m) & 0xFFFFFFFF

def model_pminmax(s1, s2, lb, unsigned, is_max):
    signed = not unsigned  # unsigned-Steuersignal (True=unsigned, signed=Default 0)
    lane_max = (1 << lb) - 1
    sign_flip = 1 << (lb - 1)
    if lb == 32:
        av = s1
        bv = s2
        ca = (av ^ sign_flip) if signed else av
        cb = (bv ^ sign_flip) if signed else bv
        neg_cb = (~cb) & lane_max
        ssum = z3.ZeroExt(1, ca) + z3.ZeroExt(1, neg_cb)
        a_gt = z3.Extract(lb, lb, ssum)
        if is_max:
            return z3.If(a_gt == 1, av, bv)
        return z3.If(a_gt == 1, bv, av)
    res = z3.BitVecVal(0, 32)
    for i in range(32 // lb):
        av = z3.Extract(i * lb + lb - 1, i * lb, s1)
        bv = z3.Extract(i * lb + lb - 1, i * lb, s2)
        ca = (av ^ sign_flip) if signed else av
        cb = (bv ^ sign_flip) if signed else bv
        neg_cb = (~cb) & lane_max
        ssum = z3.ZeroExt(1, ca) + z3.ZeroExt(1, neg_cb)
        a_gt = z3.Extract(lb, lb, ssum)
        if is_max:
            lane_res = z3.If(a_gt == 1, av, bv)
        else:
            lane_res = z3.If(a_gt == 1, bv, av)
        res = res | (z3.ZeroExt(32 - lb, lane_res) << z3.BitVecVal(i * lb, 32))
    return res

def model_psadd(s1, s2, lb, unsigned, is_sub):
    """Packed Saturating Add/Sub — bildet die ISS-Carry-Tap-Formel exakt nach
    (cin XOR cout = signed Overflow; unsigned-sub: Borrow -> Clamp 0). Sub ist
    a + ~b + 1 ($be = ~b$), NICHT $-b$-Wrap: INT_MIN-Lane mappt sonst auf sich
    selbst. inv_2=True -> Sub (PSADD orthogonalisiert)."""
    lane_max = (1 << lb) - 1
    sign = 1 << (lb - 1)
    low_mask = sign - 1
    subi = z3.BitVecVal(1, lb + 1) if is_sub else z3.BitVecVal(0, lb + 1)
    res = z3.BitVecVal(0, 32)
    for i in range(32 // lb):
        av = z3.Extract(i * lb + lb - 1, i * lb, s1)
        bv = z3.Extract(i * lb + lb - 1, i * lb, s2)
        mx = z3.BitVecVal(lane_max, lb)
        be = ((~bv) & mx) if is_sub else bv
        # carry_into_top (Bit lb-1): (av&low_mask) + (be&low_mask) + subi > low_mask
        cin_sum = z3.ZeroExt(1, (av & z3.BitVecVal(low_mask, lb))) + z3.ZeroExt(1, (be & z3.BitVecVal(low_mask, lb))) + subi
        carry_into_top = z3.UGT(cin_sum, z3.BitVecVal(low_mask, lb + 1))
        # volle lb+1-Summe (av+be+subi), carry_out = Bit lb
        sfull = z3.ZeroExt(1, av) + z3.ZeroExt(1, be) + subi
        carry_out = z3.Extract(lb, lb, sfull) == 1
        t = z3.Extract(lb - 1, 0, sfull)
        if not unsigned:
            overflow = z3.Xor(carry_into_top, carry_out)
            val = z3.If(overflow, z3.If(z3.Extract(lb - 1, lb - 1, t) == 1,
                                        z3.BitVecVal(sign - 1, lb), z3.BitVecVal(sign, lb)), t)
        else:
            if is_sub:
                val = z3.If(carry_out, t, z3.BitVecVal(0, lb))  # Borrow -> Clamp 0
            else:
                val = z3.If(carry_out, z3.BitVecVal(lane_max, lb), t)  # Overflow -> Clamp max
        res = res | (z3.ZeroExt(32 - lb, val) << z3.BitVecVal(i * lb, 32))
    return res

def model_psad(s1, s2, lb, s3=None):
    """PSAD mode 24: s3 + Summe |lane_i(s1)-lane_i(s2)|, Lane via lb (8/16/32).
    Spiegelung der ISS-Formel: lane bits aus 32-bit-Operanden, 32-Bit-Akkumulator.
    s3=None -> ohne Akkumulator (Fall ohne s3-Anteil)."""
    lane_mask = (1 << lb) - 1
    s3v = s3 if s3 is not None else z3.BitVecVal(0, 32)
    sad = z3.BitVecVal(0, 32)
    for i in range(32 // lb):
        av = z3.Extract(lb - 1 + lb * i, lb * i, s1)
        bv = z3.Extract(lb - 1 + lb * i, lb * i, s2)
        d = z3.If(z3.UGE(av, bv), av - bv, bv - av)
        sad = sad + z3.ZeroExt(32 - lb, d)
    return (sad + s3v) & 0xFFFFFFFF

def model_mul16(s1, s2):
    return ((s1 & 0xFFFF) * (s2 & 0xFFFF)) & 0xFFFFFFFF

def model_sqrom8(s1, s2):
    """SQROM8: ((a+b)^2 - a^2 - b^2) >> 1, a=s1&0xFF, b=s2&0xFF (Q115-Formel).
    Alles in 18-bit-Arithmetik: a+b max 510 (9 bit), (a+b)^2 max 260100 < 2^18,
    Diff nie negativ (Kreuzterm 2ab >= 0), Ergebnis max 65025 (16 bit)."""
    a = z3.ZeroExt(10, z3.Extract(7, 0, s1))  # 18 bit
    b = z3.ZeroExt(10, z3.Extract(7, 0, s2))  # 18 bit
    sq = (a + b) * (a + b)
    d = sq - a * a - b * b
    return z3.ZeroExt(16, z3.Extract(15, 0, d >> z3.BitVecVal(1, 18)))

def model_mul32(s1, s2, unsigned):
    i1 = z3.ZeroExt(32, s1) if unsigned else z3.SignExt(32, s1)
    i2 = z3.ZeroExt(32, s2) if unsigned else z3.SignExt(32, s2)
    prod = i1 * i2
    return (z3.Extract(31, 0, prod), z3.Extract(63, 32, prod))

def model_mul32acc(s1, s2, s3, aux, unsigned):
    i1 = z3.ZeroExt(32, s1) if unsigned else z3.SignExt(32, s1)
    i2 = z3.ZeroExt(32, s2) if unsigned else z3.SignExt(32, s2)
    prod = i1 * i2
    lo33 = z3.ZeroExt(1, z3.Extract(31, 0, prod)) + z3.ZeroExt(1, s3)
    carry_lo = z3.Extract(32, 32, lo33)
    res = z3.Extract(31, 0, lo33)
    hi = z3.Extract(63, 32, prod) + aux + z3.ZeroExt(31, carry_lo)
    return (res, hi)

def model_padd64(s1, s2, s3, aux):
    lo33 = z3.ZeroExt(1, s1) + z3.ZeroExt(1, s3)
    carry_lo = z3.Extract(32, 32, lo33)
    res = z3.Extract(31, 0, lo33)
    hi = s2 + aux + z3.ZeroExt(31, carry_lo)
    return (res, hi)

def model_div(s1, s2, unsigned):
    """DIV (K2-Semantik): res=q, aux=rem. C-Truncation (kein Floor).
    div-by-zero: q=0xFFFFFFFF, rem=s1. MIN/-1: q=MIN, rem=0 (via Wrap-Arithmetik).
    z3py kennt KEIN SDiv/SRem-Primitiv (nur UDiv/URem) -> signed via Abs+Vorzeichen."""
    if unsigned:
        return (z3.UDiv(s1, s2), z3.URem(s1, s2))
    neg = lambda x: z3.BitVecVal(0, 32) - x          # BVneg unzuverlaessig in z3py
    sa = z3.Extract(31, 31, s1) == 1
    sb = z3.Extract(31, 31, s2) == 1
    ua = z3.If(sa, neg(s1), s1)
    ub = z3.If(sb, neg(s2), s2)
    q_abs = z3.UDiv(ua, ub)
    q_neg = (q_abs ^ z3.BitVecVal(0xFFFFFFFF, 32)) + 1   # -q_abs (2er-Komplement)
    q_norm = z3.If(z3.Not(sa == sb), q_neg, q_abs)
    is_zero = (s2 == 0)
    q = z3.If(is_zero, z3.BitVecVal(0xFFFFFFFF, 32), q_norm)
    r = z3.If(is_zero, s1, s1 - q * s2)
    return (q, r)

def model_mulfma(s1, s2, s3, unsigned, sub):
    """MULFMA(ADD)/MULFMS(SUB): res = s3 ± (s1*s2)>>32, aux = lo32 (0-cost Tap).
    bit5=1 unsigned / 0 signed (MUL32-Konvention). ~0 LUT auf MUL32-Basis
    (DSP48E1 A*B+C eingebaut). MULFMS = Newton-Iteration r'=2r-b_n*r2hi 1 Pass."""
    i1 = z3.ZeroExt(32, s1) if unsigned else z3.SignExt(32, s1)
    i2 = z3.ZeroExt(32, s2) if unsigned else z3.SignExt(32, s2)
    prod = i1 * i2
    hi = z3.Extract(63, 32, prod)
    res = s3 - hi if sub else s3 + hi
    return (res, z3.Extract(31, 0, prod))

def model_pmul16(s1, s2, unsigned):
    """PMUL16: res = lo16(s1)*lo16(s2), aux = hi16(s1)*hi16(s2) — 2 unabhaengige
    Produkte (MUL32-Quadranten, kein Addierer-Baum). unsigned-Steuersignal
    (True=unsigned, signed=Default 0). Signed 16x16 max 2^30 -> kein Overflow."""
    signed = not unsigned
    if signed:
        a_lo = z3.SignExt(16, z3.Extract(15, 0, s1))
        b_lo = z3.SignExt(16, z3.Extract(15, 0, s2))
        a_hi = z3.SignExt(16, z3.Extract(31, 16, s1))
        b_hi = z3.SignExt(16, z3.Extract(31, 16, s2))
    else:
        a_lo = z3.ZeroExt(16, z3.Extract(15, 0, s1))
        b_lo = z3.ZeroExt(16, z3.Extract(15, 0, s2))
        a_hi = z3.ZeroExt(16, z3.Extract(31, 16, s1))
        b_hi = z3.ZeroExt(16, z3.Extract(31, 16, s2))
    return (z3.Extract(31, 0, a_lo * b_lo), z3.Extract(31, 0, a_hi * b_hi))


# Evaluators
def eval_z3_expr(expr):
    return z3.simplify(expr).as_long()

# Main Tester
def run_fuzzing():
    random.seed(42)
    errors = []

    print("--- STARTING SOUNDNESS FUZZING BETWEEN ISS AND Z3 MODEL ---")

    # 1. VERIFY TERNLOG
    print("Testing TERNLOG...")
    for _ in range(500):
        a_val = random.getrandbits(32)
        b_val = random.getrandbits(32)
        c_val = random.getrandbits(32)
        lut_val = random.getrandbits(8)
        
        # Concrete ISS
        res_iss = pipeline.ternlog(a_val, b_val, c_val, lut_val, 0)['res']
        # Z3 Model
        a_z3 = z3.BitVecVal(a_val, 32)
        b_z3 = z3.BitVecVal(b_val, 32)
        c_z3 = z3.BitVecVal(c_val, 32)
        lut_z3 = z3.BitVecVal(lut_val, 32)
        res_z3 = eval_z3_expr(model_ternlog(a_z3, b_z3, c_z3, lut_z3))
        
        if res_iss != res_z3:
            errors.append(("ternlog", (a_val, b_val, c_val, lut_val), res_iss, res_z3))

    # 2. VERIFY PERMB MODES
    print("Testing PERMB...")
    # Byte mode
    for _ in range(200):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        ctrl = random.getrandbits(32)
        for be in [True, False]:
            res_iss = pipeline.permb(s1, s2, ctrl, 0, False, 0, 0, mode_nibble=False, blank_enable=be)['res']
            res_z3 = eval_z3_expr(model_permb_byte(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), ctrl, blank_enable=be))
            if res_iss != res_z3:
                errors.append(("permb_byte", (s1, s2, ctrl, be), res_iss, res_z3))
    # Nibble mode
    for _ in range(200):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        ctrl = random.getrandbits(32)
        res_iss = pipeline.permb(s1, s2, ctrl, 0, False, 0, 0, mode_nibble=True, blank_enable=False)['res']
        res_z3 = eval_z3_expr(model_permb_nib(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), ctrl))
        if res_iss != res_z3:
            errors.append(("permb_nib", (s1, s2, ctrl), res_iss, res_z3))
    # Shift mode
    for _ in range(200):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        ctrl = random.getrandbits(32)
        for left in [True, False]:
            r_iss = pipeline.permb(s1, s2, ctrl, 0, False, 0, 0, shift_ctrl=True, shift_left=left)
            res_iss = r_iss['res']
            aux_iss = r_iss['aux']
            
            res_z3_expr, so_z3_expr = model_permb_shift(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), ctrl, shift_left=left)
            res_z3 = eval_z3_expr(res_z3_expr)
            aux_z3 = eval_z3_expr(so_z3_expr)
            
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append(("permb_shift", (s1, s2, ctrl, left), (res_iss, aux_iss), (res_z3, aux_z3)))

    # 3. VERIFY BITFROB MODES
    print("Testing BITFROB...")
    bitfrob_tests = [
        (BitFrobMode.LSR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_lsr(s1_z, s2_z, s3_z)),
        (BitFrobMode.LSL, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_lsl(s1_z, s2_z, s3_z)),
        (BitFrobMode.ROR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_ror(s1_z, s3_z)),
        (BitFrobMode.ASR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_asr(s1_z, s2_z, s3)),
        (BitFrobMode.BITREV8, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bitrev8(s1_z)),
        (BitFrobMode.LZC, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_lzc(s1_z)),
        (BitFrobMode.TZC, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_tzc(s1_z)),
        (BitFrobMode.MASK, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_mask(s3_z)),
        (BitFrobMode.ROL, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_rol(s1_z, s3_z)),
        (BitFrobMode.SEXT, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_sext(s1_z, s3)),
        (BitFrobMode.POPCNT_N, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_popcnt_n(s1_z)),
        (BitFrobMode.POPCNT_B, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_popcnt_b(s1_z)),
        (BitFrobMode.MASKW, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_maskw(s3_z)),
        (BitFrobMode.CLMUL_LO, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_clmul_lo(s1_z, s2_z)),
        (BitFrobMode.CLMUL_HI, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_clmul_hi(s1_z, s2_z)),
        (BitFrobMode.PARITY_B, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_parity_b(s1_z)),
        (BitFrobMode.PARITY_W, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_parity_w(s1_z)),
        (BitFrobMode.POLY_RED, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_poly_red(s1_z, cst)),
        (BitFrobMode.BITZIP_8, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bitzip8(s1_z)),
        (BitFrobMode.BITUNZIP_8, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bitunzip8(s1_z)),
        (BitFrobMode.GFNI_AFFINE, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_gfni(s1_z, s3_z)),
        (BitFrobMode.BITSWAP, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bitswap(s1_z, s2_z, s3)),
        (BitFrobMode.NIBLKP, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_niblkp(s1_z)),
        (BitFrobMode.BCD_HC, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bcdhc(s1_z, s2_z)),
        (BitFrobMode.BMATOR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bmator(s1_z, s2_z)),
        (BitFrobMode.BMATXOR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bmatxor(s1_z, s2_z)),
        (BitFrobMode.BMAT_N_OR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bmat_n(s1_z, s2_z, False)),
        (BitFrobMode.BMAT_N_XOR, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_bmat_n(s1_z, s2_z, True)),
        (BitFrobMode.LOG2, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_log2(s1_z)),
        (BitFrobMode.LOG10, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_log10(s1_z)),
        (BitFrobMode.SHR_STICKY, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_shr_sticky(s1_z, s2_z, s3_z & 7)[0]),
        (BitFrobMode.PEXT_N, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_pext_n(s1_z, s2_z)),
        (BitFrobMode.PDEP_N, lambda s1_z, s2_z, s3_z, s1, s2, s3, cst: model_pdep_n(s1_z, s2_z)),
    ]

    for mode, z3_fn in bitfrob_tests:
        # Fuzz 100 times per mode
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            s3 = random.getrandbits(32)
            cst = random.choice([0x11B, 0x13, 0x1B, 0x107, 0x11D, 0x1D]) # polys in BITFROB_CST[16..22]
            
            # run concrete ISS (POLY_RED: src3_idx = table INDEX, not poly value)
            if mode == BitFrobMode.POLY_RED:
                idx = pipeline.BITFROB_CST.index(cst)
                r_iss = pipeline.bitfrob(s1, s2, s3, mode, 0, src3_idx=idx, cst_table=True)
            else:
                r_iss = pipeline.bitfrob(s1, s2, s3, mode, 0, src3_idx=cst, cst_table=False)
            res_iss = r_iss['res']
            aux_iss = r_iss['aux']
            
            # run Z3 model
            res_z3_expr = z3_fn(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32), s1, s2, s3, cst)
            if isinstance(res_z3_expr, tuple):
                res_z3_expr, aux_z3_expr = res_z3_expr
                res_z3 = eval_z3_expr(res_z3_expr)
                aux_z3 = eval_z3_expr(aux_z3_expr)
            else:
                res_z3 = eval_z3_expr(res_z3_expr)
                # For most bitfrob modes, ISS aux is s1, check if model returns s1 too
                aux_z3 = s1 if mode not in (BitFrobMode.MASKW, BitFrobMode.SHR_STICKY) else eval_z3_expr(model_shr_sticky(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32) & 7)[1] if mode == BitFrobMode.SHR_STICKY else z3.BitVecVal(s3, 32))
            
            if res_iss != res_z3:
                errors.append((f"bitfrob_mode_{mode.name}", (s1, s2, s3, cst), f"res_iss={hex(res_iss)} res_z3={hex(res_z3)}", ""))
            if mode in (BitFrobMode.MASKW, BitFrobMode.SHR_STICKY) and aux_iss != aux_z3:
                errors.append((f"bitfrob_mode_{mode.name}_aux", (s1, s2, s3, cst), f"aux_iss={hex(aux_iss)} aux_z3={hex(aux_z3)}", ""))

    # 4. VERIFY ARITH4 SCALAR MODES
    print("Testing ARITH4 SCALAR...")
    arith_scalar_modes = [
        (ArithMode.ADD, 1, False),
        (ArithMode.ADDC, 2, False),
        (ArithMode.SATADD, 5, True),   # USATADD (unsigned saturating add)
        (ArithMode.SATADD, 5, False),  # SATADD (signed saturating add)
        (ArithMode.AVG, 6, False),
        (ArithMode.ABSADD, 7, False),
        (ArithMode.SLT, 10, True),     # SLTU
        (ArithMode.SLT, 10, False),    # SLT signed
        (ArithMode.MFC, 12, False),
        (ArithMode.ADDSHIFT1, 13, False),
        (ArithMode.ADDSHIFT2, 14, False),
    ]

    for mode_enum, mode_id, unsigned in arith_scalar_modes:
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            s3 = random.getrandbits(32)
            cin = random.choice([0, 1])
            inv1 = random.choice([True, False])
            inv2 = random.choice([True, False])
            inv3 = random.choice([True, False])
            
            # ISS (Carry lebt in flags_in: FLAG_C = 0x02, nicht als rohes 0/1)
            res_iss = pipeline.arith4(s1, s2, s3, mode_enum, pipeline.FLAG_C if cin else 0, inv_1=inv1, inv_2=inv2, inv_3=inv3, unsigned=unsigned)['res']
            # Z3
            res_z3 = eval_z3_expr(model_arith4(
                z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32),
                mode_id, c_in=z3.BitVecVal(cin, 1), inv_1=inv1, inv_2=inv2, inv_3=inv3, unsigned=unsigned
            ))
            
            if res_iss != res_z3:
                errors.append((f"arith4_scalar_mode_{mode_enum.name}", 
                               (s1, s2, s3, cin, inv1, inv2, inv3), 
                               f"iss={hex(res_iss)} z3={hex(res_z3)}", ""))

    # 5. VERIFY OTHER ARITH4 SIMD & SPECIAL MODES
    print("Testing ARITH4 PACKED/SIMD...")
    # PADD
    for lb in [8, 16]:
        optype = OpType.BYTE if lb == 8 else OpType.WORD
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            res_iss = pipeline.arith4(s1, s2, 0, ArithMode.PADD, 0, op_type_1=optype)['res']
            res_z3 = eval_z3_expr(model_padd(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), lb))
            if res_iss != res_z3:
                errors.append((f"arith4_padd_{lb}", (s1, s2), res_iss, res_z3))

    # CMP
    for lb in [8, 16, 32]:
        optype = OpType.BYTE if lb == 8 else (OpType.WORD if lb == 16 else OpType.SCALAR)
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            res_iss = pipeline.arith4(s1, s2, 0, ArithMode.CMP, 0, op_type_1=optype)['res']
            res_z3 = eval_z3_expr(model_cmp(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), lb))
            if res_iss != res_z3:
                errors.append((f"arith4_cmp_{lb}", (s1, s2), res_iss, res_z3))

    # PMINMAX
    for lb in [8, 16, 32]:
        optype = OpType.BYTE if lb == 8 else (OpType.WORD if lb == 16 else OpType.SCALAR)
        for unsigned in [True, False]:
            for is_max in [True, False]:
                mode_enum = ArithMode.PMAX if is_max else ArithMode.PMIN
                # unsigned-Steuersignal (True=unsigned, signed=Default 0); s3 wird nicht mehr gelesen
                for _ in range(50):
                    s1 = random.getrandbits(32)
                    s2 = random.getrandbits(32)
                    res_iss = pipeline.arith4(s1, s2, 0, mode_enum, 0, op_type_1=optype, unsigned=unsigned)['res']
                    res_z3 = eval_z3_expr(model_pminmax(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), lb, unsigned, is_max))
                    if res_iss != res_z3:
                        errors.append((f"arith4_pminmax_{lb}_signed{signed}_max{is_max}", (s1, s2), res_iss, res_z3))

    # PSADD (Packed Saturating Add/Sub: inv_2=True -> Sub; sub-Pfad nutzt raw src2,
    # lane-correct — INT_MIN-Lane NICHT via -b-Wrap)
    for lb in [8, 16, 32]:
        optype = OpType.BYTE if lb == 8 else (OpType.WORD if lb == 16 else OpType.SCALAR)
        for unsigned in [True, False]:
            for is_sub in [True, False]:
                for _ in range(50):
                    s1 = random.getrandbits(32)
                    s2 = random.getrandbits(32)
                    res_iss = pipeline.arith4(s1, s2, 0, ArithMode.PSADD, 0, op_type_1=optype, unsigned=unsigned, inv_2=is_sub)['res']
                    res_z3 = eval_z3_expr(model_psadd(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), lb, unsigned, is_sub))
                    if res_iss != res_z3:
                        errors.append((f"arith4_psadd_{lb}_{unsigned}_sub{is_sub}", (s1, s2), res_iss, res_z3))

    # PSAD (PSumAbs SAD, Lane via op_type_1: BYTE/WORD/SCALAR)
    for lb in [8, 16, 32]:
        optype = OpType.BYTE if lb == 8 else (OpType.WORD if lb == 16 else OpType.SCALAR)
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            s3 = random.getrandbits(32)
            res_iss = pipeline.arith4(s1, s2, s3, ArithMode.PSAD, 0, op_type_1=optype)['res']
            res_z3 = eval_z3_expr(model_psad(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), lb, z3.BitVecVal(s3, 32)))
            if res_iss != res_z3:
                errors.append((f"arith4_psad_{lb}", (s1, s2, s3), res_iss, res_z3))

    # MUL16
    for _ in range(100):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        res_iss = pipeline.arith4(s1, s2, 0, ArithMode.MUL, 0)['res']
        res_z3 = eval_z3_expr(model_mul16(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32)))
        if res_iss != res_z3:
            errors.append(("arith4_mul16", (s1, s2), res_iss, res_z3))

    # SQROM8 (Q115-Formel: ((a+b)^2-a^2-b^2)>>1, 8x8->16 via Quadrat-ROM)
    for _ in range(200):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        res_iss = pipeline.arith4(s1, s2, 0, ArithMode.SQROM8, 0)['res']
        res_z3 = eval_z3_expr(model_sqrom8(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32)))
        if res_iss != res_z3:
            errors.append(("arith4_sqrom8", (s1, s2), res_iss, res_z3))

    # MUL32
    for unsigned in [True, False]:
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            r_iss = pipeline.arith4(s1, s2, 0, ArithMode.MUL32, 0, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_mul32(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_mul32_unsigned{unsigned}", (s1, s2), (res_iss, aux_iss), (res_z3, aux_z3)))

    # MUL32ACC
    for unsigned in [True, False]:
        for _ in range(100):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            s3 = random.getrandbits(32)
            aux_in = random.getrandbits(32)
            r_iss = pipeline.arith4(s1, s2, s3, ArithMode.MUL32ACC, 0, aux_in=aux_in, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_mul32acc(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32), z3.BitVecVal(aux_in, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_mul32acc_unsigned{unsigned}", (s1, s2, s3, aux_in), (res_iss, aux_iss), (res_z3, aux_z3)))

    # PADD64
    for _ in range(100):
        s1 = random.getrandbits(32)
        s2 = random.getrandbits(32)
        s3 = random.getrandbits(32)
        aux_in = random.getrandbits(32)
        r_iss = pipeline.arith4(s1, s2, s3, ArithMode.PADD64, 0, aux_in=aux_in)
        res_iss, aux_iss = r_iss['res'], r_iss['aux']
        res_z3_exp, aux_z3_exp = model_padd64(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32), z3.BitVecVal(aux_in, 32))
        res_z3 = eval_z3_expr(res_z3_exp)
        aux_z3 = eval_z3_expr(aux_z3_exp)
        if res_iss != res_z3 or aux_iss != aux_z3:
            errors.append(("arith4_padd64", (s1, s2, s3, aux_in), (res_iss, aux_iss), (res_z3, aux_z3)))

    # DIV (K2: C-Truncation, div-zero definiert, MIN/-1 = MIN/0). Edge-Cases + random.
    for unsigned in [True, False]:
        edge_pairs = [(0, 0), (1, 0), (123, 0), (0xFFFFFFFF, 0), (0x80000000, 0),
                      (0x80000000, 0xFFFFFFFF), (0x7FFFFFFF, 0xFFFFFFFF),
                      (0x80000000, 1), (0xFFFFFFFF, 1), (1, 0xFFFFFFFF), (0xFFFFFFFF, 0xFFFFFFFF)]
        for s1, s2 in edge_pairs:
            r_iss = pipeline.arith4(s1, s2, 0, ArithMode.DIV, 0, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_div(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_div_edge_unsigned{unsigned}", (s1, s2), (res_iss, aux_iss), (res_z3, aux_z3)))
        for _ in range(200):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            r_iss = pipeline.arith4(s1, s2, 0, ArithMode.DIV, 0, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_div(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_div_unsigned{unsigned}", (s1, s2), (res_iss, aux_iss), (res_z3, aux_z3)))

    # MULFMA (ADD s3+hi) / MULFMS (SUB s3-hi): FMA auf hi32. unsigned-Steuersignal.
    for mode, sub in ((ArithMode.MULFMA, False), (ArithMode.MULFMS, True)):
        for unsigned in [True, False]:
            edge_tri = [(0, 0, 0), (0xFFFFFFFF, 0xFFFFFFFF, 0),
                        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
                        (0x80000000, 0x80000000, 0x7FFFFFFF),
                        (1, 1, 1), (0xFFFFFFFF, 1, 0xFFFFFFFF),
                        (0x12345678, 0x9ABCDEF0, 0xDEADBEEF)]
            for s1, s2, s3 in edge_tri:
                r_iss = pipeline.arith4(s1, s2, s3, mode, 0, unsigned=unsigned)
                res_iss, aux_iss = r_iss['res'], r_iss['aux']
                res_z3_exp, aux_z3_exp = model_mulfma(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32), unsigned, sub)
                res_z3 = eval_z3_expr(res_z3_exp)
                aux_z3 = eval_z3_expr(aux_z3_exp)
                if res_iss != res_z3 or aux_iss != aux_z3:
                    errors.append((f"arith4_mulfma_{mode.name}_{unsigned}_edge", (s1, s2, s3), (res_iss, aux_iss), (res_z3, aux_z3)))
            for _ in range(100):
                s1 = random.getrandbits(32)
                s2 = random.getrandbits(32)
                s3 = random.getrandbits(32)
                r_iss = pipeline.arith4(s1, s2, s3, mode, 0, unsigned=unsigned)
                res_iss, aux_iss = r_iss['res'], r_iss['aux']
                res_z3_exp, aux_z3_exp = model_mulfma(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), z3.BitVecVal(s3, 32), unsigned, sub)
                res_z3 = eval_z3_expr(res_z3_exp)
                aux_z3 = eval_z3_expr(aux_z3_exp)
                if res_iss != res_z3 or aux_iss != aux_z3:
                    errors.append((f"arith4_mulfma_{mode.name}_{unsigned}", (s1, s2, s3), (res_iss, aux_iss), (res_z3, aux_z3)))

    # PMUL16: res=lo16*lo16, aux=hi16*hi16 (MUL32-Quadranten-Split). unsigned-Steuersignal (s3 frei).
    for unsigned in [True, False]:
        edge_pairs = [(0, 0), (0xFFFFFFFF, 0xFFFFFFFF), (0x80008000, 0x80008000),
                      (0xFFFF0000, 0x0000FFFF), (0x80000000, 0xFFFFFFFF),
                      (0x0000FFFF, 0x0000FFFF), (0x12345678, 0x9ABCDEF0)]
        for s1, s2 in edge_pairs:
            r_iss = pipeline.arith4(s1, s2, 0, ArithMode.PMUL16, 0, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_pmul16(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_pmul16_{unsigned}_edge", (s1, s2), (res_iss, aux_iss), (res_z3, aux_z3)))
        for _ in range(200):
            s1 = random.getrandbits(32)
            s2 = random.getrandbits(32)
            r_iss = pipeline.arith4(s1, s2, 0, ArithMode.PMUL16, 0, unsigned=unsigned)
            res_iss, aux_iss = r_iss['res'], r_iss['aux']
            res_z3_exp, aux_z3_exp = model_pmul16(z3.BitVecVal(s1, 32), z3.BitVecVal(s2, 32), unsigned)
            res_z3 = eval_z3_expr(res_z3_exp)
            aux_z3 = eval_z3_expr(aux_z3_exp)
            if res_iss != res_z3 or aux_iss != aux_z3:
                errors.append((f"arith4_pmul16_{unsigned}", (s1, s2), (res_iss, aux_iss), (res_z3, aux_z3)))

    # --- PRINT SUMMARY ---
    print(f"\nFuzzing finished. Mismatches found: {len(errors)}")
    if errors:
        print("\n--- DETAILED MISMATCHES ---")
        for tag, inputs, iss, z3_val in errors[:20]:
            print(f"Mismatch in {tag} with inputs {inputs}:")
            print(f"  ISS Output: {iss}")
            print(f"  Z3 Output:  {z3_val}")
        if len(errors) > 20:
            print(f"... and {len(errors) - 20} more mismatches.")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED! Z3 models are equivalent to the Python reference ISS!")
        sys.exit(0)

if __name__ == "__main__":
    run_fuzzing()
