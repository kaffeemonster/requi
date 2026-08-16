# --- Gemeinsame Helfer + ctrl-Dicts fuer Mikrocode-Tests ---
# Aus pipeline.main() extrahiert (S2), keine Semantik-Aenderung.
from pipeline import *  # Kern-Primitives; pipeline definiert alle Namen vor dem Importpunkt (import-sicher)
__all__ = [  # explizit, damit `from helpers import *` auch Unterstrich-Namen bindet
    '_b_perm',
    '_b_bitf',
    '_b_tern',
    '_b_arit',
    'ctrl_popcnt_full',
    '_ctrl_gray',
    'gray_to_bin_step',
    'gray_to_bin',
    'ctz_mul_step',
    'mul_ctz',
    '_bp_ctrl',
    'shift_right',
    'shift_left',
    'mul_full',
    '_bp',
    'gf256_mul_py',
    'gf256_mul_pipe',
    'AES_POLY',
    'xtime_pipe',
    'c_bs',
    'transpose_8x8',
    'bitzip_byte',
    'bitunzip_word',
    'imm_encode',
    'gf256_mul',
    'GF256_INV',
    'AES_SBOX_REF',
    'ctrl_subb_lo',
    'ctrl_subb_hi',
    'ctrl_mul',
    'ctrl_muladd',
    'mul32x32',
    'mulhi32x32',
    'sx64',
    'mul32_hw',
    'mulhi_hw',
    'mul32u_hw',
    'mulhiu_hw',
    'log2_micro',
    'log10_micro',
    'mul16_sqrom',
    'ctrl_mul32',
    'ctrl_mul32acc',
    'FWD_MAP',
    'INV_MAP',
    'GF4_POLY',
    'LAM',
    '_gf4_mul',
    '_map_vec',
    '_composite_inv',
    '_composite_sbox',
    '_l_and',
    '_l_or',
    '_l_xor',
    '_l_not',
    'pext32',
    'pext_ref',
    'pdep_ref',
    'pdep32'
]

_b_perm = {'src3_idx': 0, 'cst_table': False, 'imm6': 0, 'mode_nibble': False, 'blank_enable': False, 'prev_in_strobe': 8, 'write_flags': False, 'read_flags': False, 'internal_table': False}
_b_bitf = {'mode_imm6': BitFrobMode.LSR, 'inv_1': False, 'inv_2': False, 'inv_3': False, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False}
_b_tern = {'tern_lut': 0x00, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False}
_b_arit = {'mode_imm6': ArithMode.ADD, 'inv_1': False, 'inv_2': False, 'inv_3': False, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False}
ctrl_popcnt_full = [
    {'permb': dict(_b_perm), 'bitfrob': dict(_b_bitf, mode_imm6=BitFrobMode.POPCNT_B, prev_in_strobe=0), 'ternlog': dict(_b_tern), 'arith4': dict(_b_arit)},
    {'permb': dict(_b_perm), 'bitfrob': dict(_b_bitf), 'ternlog': dict(_b_tern), 'arith4': dict(_b_arit, mode_imm6=ArithMode.PWADD, op_type_1=OpType.BYTE, prev_in_strobe=1)},
    {'permb': dict(_b_perm), 'bitfrob': dict(_b_bitf), 'ternlog': dict(_b_tern), 'arith4': dict(_b_arit, mode_imm6=ArithMode.PWADD, op_type_1=OpType.WORD, prev_in_strobe=1)},
]
_ctrl_gray = {
    'permb':   {**_b_perm, 'prev_in_strobe': 0, 'write_flags': False, 'read_flags': False},
    'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSR, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False},
    'ternlog': {**_b_tern, 'tern_lut': TernLut.XOR, 'prev_in_strobe': 1,  # a = bitfrob res = x>>1
                'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False},
    'arith4':  {**_b_arit, 'mode_imm6': ArithMode.ADD, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False},
}
def gray_to_bin_step(x_val, shift):
    """1 Makro-Schritt: x ^= x>>shift. in_c=shift steuert LSR-Betrag,
    ternlog c=0 via cst_table (TERNLOG_CST[0]=0x0).
    shift <= 7: bitfrob LSR fein. shift >= 8: permb Escape-Vektor
    (x>>8=Vektor [1,2,3,4], x>>16=[2,3,4,5])."""
    if shift <= 7:
        return execute_microcode(x_val, x_val, shift, {
            'permb':   {**_b_perm, 'prev_in_strobe': 0},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSR,
                        'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False,
                        'write_flags': False, 'read_flags': False, 'internal_table': False},
            'ternlog': {**_b_tern, 'tern_lut': TernLut.XOR, 'prev_in_strobe': 1,
                        'cst_table': True, 'src3_idx': 0},
            'arith4':  {**_b_arit, 'mode_imm6': ArithMode.ADD, 'prev_in_strobe': 8},
        })
    # shift >= 8: permb Escape-Vektor fuer x>>shift, bitfrob Bypass
    vec = 0x04030201 if shift == 8 else 0x05040302  # [1,2,3,4] / [2,3,4,5]
    return execute_microcode(0, x_val, vec, {
        'permb':   {**_b_perm, 'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False,
                    'imm6': 0, 'mode_nibble': False, 'blank_enable': False,
                    'write_flags': False, 'read_flags': False, 'internal_table': False},
        'bitfrob': {**_b_bitf, 'prev_in_strobe': 8},
        'ternlog': {**_b_tern, 'tern_lut': TernLut.XOR, 'prev_in_strobe': 1,
                    'cst_table': True, 'src3_idx': 0},
        'arith4':  {**_b_arit, 'mode_imm6': ArithMode.ADD, 'prev_in_strobe': 8},
    })
def gray_to_bin(gray_val):
    """x = gray; for shift in [1,2,4,8,16]: x ^= x>>shift.
    shift<=7 via LSR fein, shift>=8 via permb Escape-Vektor."""
    x = gray_val
    for shift in [1, 2, 4, 8, 16]:
        x = gray_to_bin_step(x, shift)
    return x
def mul16_sqrom(a, b):
    """16x16 unsigned via 4x SQROM8 (Quadrat-ROM) + Schulbuch-Komposition.
    SQROM8 maskiert s1/s2 intern auf 8 bit -> low/cross-Quadranten ohne
    Extraktion; ah/bh via permb-LSR8-Escape-Vektor [1,2,3,4] (concat=in_b||in_a).
    11 Passes: 2x LSR8 + 4x SQROM8 + 1x ADD (cross) + LSL16/LSL8 + 2x ADD.
    Komposition p_hi<<16 + cross<<8 + p_lo: LSL16-Vektor [0,1,4,5],
    LSL8-Vektor [0,4,5,6] (concat=in_b||in_a: in_b=0 obere, in_a=Wert untere).
    Q115 (pipeline_smt.py M20) beweist die SQROM8-Formel; die 16x16-Komposition
    ist z3-QF_BV-unbeweisbar (Q116 --stretch, Distributiv-Grenze) ->
    TEST 47 + Fuzzer-Konkret. 8x8-Referenz-Variante: SQROM8-Mode direkt."""
    def _run(ctrl, ia, ib, ic, pv=0):
        return execute_pipeline(ia, ib, ic, ctrl, pv, 0)['res']
    ctrl_lsr = {'permb': dict(_b_perm, prev_in_strobe=0), 'bitfrob': dict(_b_bitf),
                'ternlog': dict(_b_tern), 'arith4': dict(_b_arit)}
    ah = _run(ctrl_lsr, 0, a, 0x04030201)  # a>>8
    bh = _run(ctrl_lsr, 0, b, 0x04030201)  # b>>8
    ctrl_sq = {'permb': dict(_b_perm), 'bitfrob': dict(_b_bitf), 'ternlog': dict(_b_tern),
               'arith4': dict(_b_arit, mode_imm6=ArithMode.SQROM8, prev_in_strobe=0)}
    p_hi = _run(ctrl_sq, ah, bh, 0)  # ah*bh
    p_lo = _run(ctrl_sq, a, b, 0)    # al*bl (intern maskiert)
    c1 = _run(ctrl_sq, ah, b, 0)     # ah*bl
    c2 = _run(ctrl_sq, a, bh, 0)     # al*bh
    ctrl_add = {'permb': dict(_b_perm), 'bitfrob': dict(_b_bitf), 'ternlog': dict(_b_tern),
                'arith4': dict(_b_arit, mode_imm6=ArithMode.ADD, prev_in_strobe=0)}
    cross = _run(ctrl_add, c1, c2, 0)  # <= 130050, kein Overflow
    ctrl_lsl = {'permb': dict(_b_perm, prev_in_strobe=0), 'bitfrob': dict(_b_bitf),
                'ternlog': dict(_b_tern), 'arith4': dict(_b_arit)}
    hi_s = _run(ctrl_lsl, p_hi, 0, 0x05040100)   # p_hi<<16
    cr_s = _run(ctrl_lsl, cross, 0, 0x06050400)  # cross<<8
    tmp = _run(ctrl_add, hi_s, cr_s, 0)
    return _run(ctrl_add, tmp, p_lo, 0)
def ctz_mul_step(a, b, res, step_count):
    """Eine Loop-Iteration: ctz(b) verschobene a+b, einmal add, shift.
    Returns (new_a, new_b, new_res, step_count+1).
    Jeder Sub-Schritt = 1 execute_pipeline Aufruf mit explizitem prev_in."""
    # CTZ von b (TZC, s3=egal)
    ctrl_tz = {
        'permb':   {**_b_perm},
        'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.TZC, 'prev_in_strobe': 0},
        'ternlog': {**_b_tern},
        'arith4':  {**_b_arit},
    }
    tz = execute_pipeline(b, 0, 0, ctrl_tz, 0, 0)['res'] & 0x1F

    if tz > 0:
        # a <<= tz (LSL amt=tz)
        ctrl_ashl = {
            'permb':   {**_b_perm},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSL, 'cst_table': False, 'prev_in_strobe': 0},
            'ternlog': {**_b_tern},
            'arith4':  {**_b_arit},
        }
        a = execute_pipeline(a, 0, tz, ctrl_ashl, 0, 0)['res'] & MASK_RLEN
        # b >>= tz (LSR amt=tz)
        ctrl_blsr = {
            'permb':   {**_b_perm},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSR, 'cst_table': False, 'prev_in_strobe': 0},
            'ternlog': {**_b_tern},
            'arith4':  {**_b_arit},
        }
        b = execute_pipeline(0, b, tz, ctrl_blsr, 0, 0)['res'] & MASK_RLEN

    if b & 1:
        # res += a: alle Stufen Bypass, arith4 a=prev_in=res (via strobe 1), b=in_b=a
        ctrl_add = {
            'permb':   {**_b_perm},
            'bitfrob': {**_b_bitf},
            'ternlog': {**_b_tern},
            'arith4':  {**_b_arit, 'prev_in_strobe': 1, 'cst_table': False},
        }
        res = execute_pipeline(res, a, 0, ctrl_add, res, 0)['res'] & MASK_RLEN

    # a <<= 1, b >>= 1 (nur wenn Merker nicht getragen)
    if step_count < 31:
        ctrl_a1 = {
            'permb':   {**_b_perm},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSL, 'cst_table': False, 'prev_in_strobe': 0},
            'ternlog': {**_b_tern},
            'arith4':  {**_b_arit},
        }
        a = execute_pipeline(a, 0, 1, ctrl_a1, 0, 0)['res'] & MASK_RLEN
        ctrl_b1 = {
            'permb':   {**_b_perm},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSR, 'cst_table': False, 'prev_in_strobe': 0},
            'ternlog': {**_b_tern},
            'arith4':  {**_b_arit},
        }
        b = execute_pipeline(0, b, 1, ctrl_b1, 0, 0)['res'] & MASK_RLEN

    return a, b, res, step_count + 1
def mul_ctz(a, b):
    """8-Bit MUL via CTZ-accelerated shift-add. Operanden <= 0xFF.
    LSR/LSL fein 0..7 Bit — 8-Bit MUL bleibt innerhalb des Limits.
    Produziert 16-Bit Result, low word = MUL, high word = MULHI."""
    a, b = a & 0xFF, b & 0xFF
    res = 0
    step = 0
    loops = 0
    while b != 0 and loops < 32:
        a, b, res, step = ctz_mul_step(a, b, res, step)
        loops += 1
    return res & 0xFFFF  # 16-Bit Produkt
_bp_ctrl = {
    'permb':   {**_b_perm, 'prev_in_strobe': 0, 'cst_table': False},
    'bitfrob': {**_b_bitf, 'prev_in_strobe': 8},
    'ternlog': {**_b_tern, 'prev_in_strobe': 8},
    'arith4':  {**_b_arit, 'prev_in_strobe': 8},
}
def shift_right(x, n):
    """x >> n, 0 <= n <= 31. Byte-Shifts via permb Escape-Vektoren,
    Fine-Shifts 0..7 via bitfrob LSR."""
    x &= MASK_RLEN
    if n == 0: return x
    res = x
    vmap = {8: PERMB_SHIFT_VEC['LSR8'], 16: PERMB_SHIFT_VEC['LSR16'], 24: PERMB_SHIFT_VEC['LSR24']}
    for bshift in (24, 16, 8):
        if n >= bshift:
            res = execute_microcode(0, res, vmap[bshift], _bp_ctrl)
            n -= bshift
    if n > 0:
        res = execute_microcode(0, res, n, {
            'permb':   {**_b_perm, 'prev_in_strobe': 8},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSR, 'prev_in_strobe': 0, 'cst_table': False},
            'ternlog': {**_b_tern, 'prev_in_strobe': 8},
            'arith4':  {**_b_arit, 'prev_in_strobe': 8},
        })
    return res & MASK_RLEN
def shift_left(x, n):
    """x << n, 0 <= n <= 31. Byte-Shifts via permb Escape-Vektoren,
    Fine-Shifts 0..7 via bitfrob LSL."""
    x &= MASK_RLEN
    if n == 0: return x
    res = x
    vmap = {8: PERMB_SHIFT_VEC['LSL8'], 16: PERMB_SHIFT_VEC['LSL16'], 24: PERMB_SHIFT_VEC['LSL24']}
    for bshift in (24, 16, 8):
        if n >= bshift:
            res = execute_microcode(0, res, vmap[bshift], _bp_ctrl)
            n -= bshift
    if n > 0:
        # LSL fine: Funnel-Shift braucht Wert in s1 (High-Haelfte), s2=0.
        # concat = (s1<<32)|s2 = (res<<32)|0, concat<<amt>>32 = res<<amt.
        res = execute_microcode(res, 0, n, {
            'permb':   {**_b_perm, 'prev_in_strobe': 8},
            'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LSL, 'prev_in_strobe': 0, 'cst_table': False},
            'ternlog': {**_b_tern, 'prev_in_strobe': 8},
            'arith4':  {**_b_arit, 'prev_in_strobe': 8},
        })
    return res & MASK_RLEN
def mul_full(a, b):
    """32x32 -> 64-Bit MUL via CTZ-accelerated shift-add.
    Returns (MUL=lo, MULHI=hi). TZC + arith4 Carry-Flag via Pipeline;
    64-Bit Shifts via native Python (Makro-Schritt Reg-File)."""
    a, b = a & MASK_RLEN, b & MASK_RLEN
    # 64-Bit Multiplikator
    a_hi, a_lo = 0, a
    lo = hi = 0
    loops = 0

    ctrl_tz = {
        'permb':   {**_b_perm, 'prev_in_strobe': 8},
        'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.TZC, 'prev_in_strobe': 0},
        'ternlog': {**_b_tern, 'prev_in_strobe': 8},
        'arith4':  {**_b_arit, 'prev_in_strobe': 8},
    }
    ctrl_add = {
        'permb':   {**_b_perm, 'prev_in_strobe': 8},
        'bitfrob': {**_b_bitf, 'prev_in_strobe': 8},
        'ternlog': {**_b_tern, 'prev_in_strobe': 8},
        'arith4':  {**_b_arit, 'mode_imm6': ArithMode.ADD, 'prev_in_strobe': 1,
                    'write_flags': True, 'cst_table': False},
    }

    while b != 0 and loops < 128:
        loops += 1
        # TZC b (Pipeline: bitfrob TZC)
        tz = execute_pipeline(b, 0, 0, ctrl_tz, 0, 0)['res'] & 0x1F

        if tz:
            # 64-Bit Shift (Makro-Schritt: Reg-File, kein neues HW)
            a_64 = (a_hi << 32) | a_lo
            a_64 <<= tz
            a_hi = (a_64 >> 32) & MASK_RLEN
            a_lo = a_64 & MASK_RLEN
            b >>= tz

        if b & 1:
            # lo += a_lo (Pipeline: arith4 ADD mit prev_in)
            res_add = execute_pipeline(lo, a_lo, 0, ctrl_add, lo, 0)
            lo = res_add['res'] & MASK_RLEN
            add_carry = 1 if (res_add['flags'] & FLAG_C) else 0
            hi = (hi + a_hi + add_carry) & MASK_RLEN

        # a <<= 1, b >>= 1 (64-Bit, Makro-Schritt)
        a_64 = (a_hi << 32) | a_lo
        a_64 <<= 1
        a_hi = (a_64 >> 32) & MASK_RLEN
        a_lo = a_64 & MASK_RLEN
        b >>= 1

    return lo, hi
_bp = { 'permb': { 'src3_idx': 0, 'cst_table': True, 'imm6': 0, 'mode_nibble': False,
       'blank_enable': True, 'prev_in_strobe': 8, 'write_flags': False,
       'read_flags': False, 'internal_table': False },
       'bitfrob': { 'mode_imm6': BitFrobMode.LSR, 'inv_1': False, 'inv_2': False, 'inv_3': False, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False },
       'ternlog': { 'tern_lut': 0, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False },
       'arith4': { 'mode_imm6': ArithMode.ADD, 'inv_1': False, 'inv_2': False, 'inv_3': False, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False }}
def gf256_mul_py(a, b, poly=0x11B):
    p = 0
    for i in range(8):
        if b & (1 << i):
            p ^= a << i
    for i in range(14, 7, -1):
        if p & (1 << i):
            p ^= poly << (i - 8)
    return p & 0xFF
def gf256_mul_pipe(a, b, poly=0x11B):
    c_bitf_lo = dict(_b_bitf)
    c_bitf_lo['mode_imm6'] = BitFrobMode.CLMUL_LO
    c_bitf_lo['prev_in_strobe'] = 0
    c_lo = { 'permb':dict(_b_perm), 'bitfrob':c_bitf_lo, 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
    lo = execute_pipeline(a, b, 0, c_lo, 0, 0)['res'] & 0xFF

    c_bitf_hi = dict(c_bitf_lo)
    c_bitf_hi['mode_imm6'] = BitFrobMode.CLMUL_HI
    c_hi = { 'permb':dict(_b_perm), 'bitfrob':c_bitf_hi, 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
    hi = execute_pipeline(a, b, 0, c_hi, 0, 0)['res'] & 0xFF

    product = (hi << 8) | lo

    c_bitf_red = dict(_b_bitf)
    c_bitf_red['mode_imm6'] = BitFrobMode.POLY_RED
    c_bitf_red['prev_in_strobe'] = 0
    c_red = { 'permb':dict(_b_perm), 'bitfrob':c_bitf_red, 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
    return execute_pipeline(product, 0, poly, c_red, 0, 0)['res'] & 0xFF
AES_POLY = 0x11B  # x^8 + x^4 + x^3 + x + 1
def xtime_pipe(x):
    # bitfrob LSL(1): x << 1
    c_bf = dict(_b_bitf)
    c_bf['mode_imm6'] = BitFrobMode.LSL
    c_bf['prev_in_strobe'] = 0
    c_shift = { 'permb':dict(_b_perm), 'bitfrob':c_bf, 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
    # LSL: s1=value, s2=0 (funnel shift needs value in s1 for LSL)
    shifted = execute_pipeline(x, 0, 1, c_shift, 0, 0)['res'] & MASK_RLEN

    # POLY_RED: reduce if >= 0x100
    c_bf2 = dict(_b_bitf)
    c_bf2['mode_imm6'] = BitFrobMode.POLY_RED
    c_bf2['prev_in_strobe'] = 0
    c_red = { 'permb':dict(_b_perm), 'bitfrob':c_bf2, 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
    return execute_pipeline(shifted, 0, AES_POLY, c_red, 0, 0)['res'] & 0xFF
c_bs = { 'permb':dict(_b_perm), 'bitfrob':dict(_b_bitf), 'ternlog':dict(_b_tern), 'arith4':dict(_b_arit) }
c_bs['bitfrob']['mode_imm6'] = BitFrobMode.BITSWAP
c_bs['bitfrob']['prev_in_strobe'] = 0

def transpose_8x8(hi32, lo32):
    """8x8 Bit-Transpose: 64-Bit Block (hi32=obere 4 Bytes, lo32=untere 4 Bytes). 6 Passes total."""
    # Stage 1: swap adjacent bits (mask=0x5555_5555, shift=1) on both halves
    out_lo = execute_pipeline(lo32, 0x55555555, 1, c_bs, 0, 0)['res']
    out_hi = execute_pipeline(hi32, 0x55555555, 1, c_bs, 0, 0)['res']
    # Stage 2: swap bit-pairs (mask=0x3333_3333, shift=2)
    out_lo = execute_pipeline(out_lo, 0x33333333, 2, c_bs, 0, 0)['res']
    out_hi = execute_pipeline(out_hi, 0x33333333, 2, c_bs, 0, 0)['res']
    # Stage 3: swap nibbles (mask=0x0F0F_0F0F, shift=4)
    out_lo = execute_pipeline(out_lo, 0x0F0F0F0F, 4, c_bs, 0, 0)['res']
    out_hi = execute_pipeline(out_hi, 0x0F0F0F0F, 4, c_bs, 0, 0)['res']
    return out_hi, out_lo
def bitzip_byte(val, byte_idx):
    """ZIP byte at position byte_idx*8 of val, return 16-bit result."""
    shifted = (val >> (byte_idx * 8)) & 0xFF
    out = execute_pipeline(shifted, 0, 0,
        {'permb': dict(_b_perm),
         'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.BITZIP_8, 'prev_in_strobe': 0},
         'ternlog': dict(_b_tern),
         'arith4': dict(_b_arit)}, 0, 0)
    return out['res'] & 0xFFFF
def bitunzip_word(val16):
    """UNZIP compact 16-bit → 8-bit."""
    out = execute_pipeline(val16, 0, 0,
        {'permb': dict(_b_perm),
         'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.BITUNZIP_8, 'prev_in_strobe': 0},
         'ternlog': dict(_b_tern),
         'arith4': dict(_b_arit)}, 0, 0)
    return out['res'] & 0xFF
def imm_encode(val, width=32):
    """Classify 32-bit immediate by cheapest construction method.
    Returns (method, encoding_dict).
    Methods: 'zero', 'maskw', 'maskw_shift', 'signext', 'replicate', 'permb', 'synthesize'.
    'synthesize' = needs 2 ops (e.g. LSL+ORI, or maskw+ternlog AND).
    Not 'ARM64' — our own encoding scheme using pipeline primitives.
    """
    val &= (1 << width) - 1
    if val == 0: return ('zero', {})

    # 1. Contiguous mask? MASKW can create (1<<w)-1, 0=all-ones
    for w in range(1, width + 1):
        m = ((1 << width) - 1) if w == width else (1 << w) - 1
        if val == m: return ('maskw', {'width': w if w < width else 0, 'invert': False})
        if val == ((~m) & ((1 << width) - 1)):
            return ('maskw', {'width': w if w < width else 0, 'invert': True})

    # 2. Contiguous mask shifted? MASKW + LSL
    # One-pass: MASKW creates mask, bitfrob LSL shifts — but LSL consumes bitfrob.
    # Two-pass microcode. Or: ternlog mask_mode(width) ← wrong alignment.
    # Better: maskw_shift = 2-step (maskw(width) + LSL). Note it, return 'maskw_shift'.
    for lsb in range(1, width):
        shifted_mask = ((1 << width) - 1) << lsb
        # MASKW creates (1<<(w-lsb))-1, then LSL by lsb
        for w in range(lsb + 1, width + 1):
            m = (1 << (w - lsb)) - 1
            if val == (m << lsb):
                return ('maskw_shift', {'width': w - lsb, 'lsb': lsb, 'invert': False})

    # 3. Replicated bit-pattern? Like logical imm.
    # Check periods: 2, 4, 8, 16 bits. Before signext — signext is degenerate for many values.
    for p in [2, 4, 8, 16]:
        if p >= width: continue
        pat = val & ((1 << p) - 1)
        replicated = pat
        for i in range(p, width, p):
            replicated |= pat << i
        if val == replicated:
            return ('replicate', {'pattern': pat, 'period': p})

    # 3b. Replicated + rotated?
    for p in [2, 4, 8, 16]:
        if p >= width: continue
        pat = val & ((1 << p) - 1)
        for rot in range(p):
            rpat = ((pat >> (p - rot)) | (pat << rot)) & ((1 << p) - 1)
            replicated = rpat
            for i in range(p, width, p):
                replicated |= rpat << i
            if val == replicated and rot > 0:
                return ('replicate', {'pattern': pat, 'period': p, 'rotate': rot})

    # 4. Sign-extended? bitfrob SEXT — source must be cheap (≤ 16 bits)
    for pos in range(1, min(width - 1, 17)):  # max pos=16, source ≤ 17 bits
        low = val & ((1 << (pos + 1)) - 1)
        reconstructed = low | (((1 << width) - 1) & ~((1 << (pos + 1)) - 1))
        # Guard: Sign-Extend nur wenn Vorzeichen-Bit (pos) gesetzt — spiegelt
        # bitfrob-SEXT-Semantik (pipeline.py: res = low, sonst). Ohne Guard wuerde
        # z.B. 0xfffffffd (obere Bits 1, Bit1=0) faelschlich pos=1 matchen.
        if (low & (1 << pos)) and val == reconstructed:
            return ('signext', {'pos': pos, 'value': low})

    # 5. PERMB_CST? Check 16 ISA-visible entries.
    for idx in range(16):
        cst = PERMB_CST[idx]
        lo32 = cst & MASK_RLEN
        hi32 = (cst >> 32) & MASK_RLEN
        if val == lo32 or val == hi32 or val == (cst & 0xFFFFFFFF):
            return ('permb', {'idx': idx, 'hi': (val == hi32)})

    # 6. Synthesize: 2 ops needed (e.g. MOV(hi) | OR(lo), or mask+ternlog combine)
    # Simple heuristic: can we build it as MOV(hi16) | MOV(lo16) via LSL+OR?
    lo16 = val & 0xFFFF
    hi16 = (val >> 16) & 0xFFFF
    if lo16 == 0:
        # lo explizit 0, hi=hi16: ((hi<<16)|0) == val — konsistent mit lsl16_or bei lo16!=0
        return ('synthesize', {'method': 'lsl16_or', 'lo': 0, 'hi': hi16, 'shift': 16})
    if hi16 == 0:
        return ('synthesize', {'method': 'mov_lo', 'lo': lo16})
    return ('synthesize', {'method': 'lsl16_or', 'lo': lo16, 'hi': hi16, 'shift': 16})
def gf256_mul(a, b, poly=0x11B):
    """GF(2^8) multiply, poly AES 0x11B (x^8+x^4+x^3+x+1)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= (poly & 0xFF)
        b >>= 1
    return p
GF256_INV = [0] * 256
AES_SBOX_REF = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
]
ctrl_subb_lo = {
    'permb':   _b_perm.copy(),
    'bitfrob': _b_bitf.copy(),
    'ternlog': _b_tern.copy(),
    'arith4':  {'mode_imm6': ArithMode.ADDC, 'inv_1': False, 'inv_2': True, 'inv_3': False, 'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False, 'write_flags': True, 'read_flags': False, 'internal_table': False, 'op_type_1': OpType.SCALAR, 'op_type_2': OpType.SCALAR, 'op_type_3': OpType.SCALAR},
}
ctrl_subb_hi = {
    'permb':   _b_perm.copy(),
    'bitfrob': _b_bitf.copy(),
    'ternlog': _b_tern.copy(),
    'arith4':  {'mode_imm6': ArithMode.ADDC, 'inv_1': False, 'inv_2': True, 'inv_3': False, 'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False, 'write_flags': False, 'read_flags': False, 'internal_table': False, 'op_type_1': OpType.SCALAR, 'op_type_2': OpType.SCALAR, 'op_type_3': OpType.SCALAR},
}
ctrl_mul = {
    'permb':   _b_perm.copy(),
    'bitfrob': _b_bitf.copy(),
    'ternlog': _b_tern.copy(),
    'arith4':  {'mode_imm6': ArithMode.MUL, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False, 'write_flags': False,
                'read_flags': False, 'internal_table': False, 'op_type_1': OpType.SCALAR,
                'op_type_2': OpType.SCALAR, 'op_type_3': OpType.SCALAR},
}
ctrl_muladd = ctrl_mul.copy()
def mul32x32(a, b):
    """Full 32×32→64 multiply via macro-microcode. Returns (lo32, hi32).

    Schoolbook decomposition:
      a = a_hi<<16 | a_lo,  b = b_hi<<16 | b_lo
      z00 = a_lo*b_lo, z01 = a_lo*b_hi, z10 = a_hi*b_lo, z11 = a_hi*b_hi
      Full product = z00 + (z01+z10)<<16 + z11<<32

    Macro-steps (each = 1 pipeline pass, register file between steps):
      Pass1: MUL(a_lo, b_lo) → reg P0  (z00)
      Pass2: MUL(a_lo, b_hi) → reg P1  (z01)
      Pass3: MUL(a_hi, b_lo) → reg P2  (z10)
      Pass4: MUL(a_hi, b_hi) → reg P3  (z11)

    Accumulation (macro-microcode with register file + shift primitives):
      lo32 = z00[15:0] + z01[15:0]<<16 + z10[15:0]<<16
      hi32 = z11 + z01[31:16] + z10[31:16] + carry from lo32

    Decoder synthesizes LSR16(permb) + AND 0xFFFF(ternlog) for each hi/lo split.
    PWADD WORD accumulates the 3 terms into lo32/hi32 in ~3 more macro-steps.
    Total: ~7 macro-steps (4 MUL + 3 PWADD/ADD).
    """
    a_lo, a_hi = a & 0xFFFF, (a >> 16) & 0xFFFF
    b_lo, b_hi = b & 0xFFFF, (b >> 16) & 0xFFFF

    # Each macro-step: compute one 16×16 partial via pipeline, writeback to register
    z00 = execute_microcode(a_lo, b_lo, 0, [ctrl_mul])
    z01 = execute_microcode(a_lo, b_hi, 0, [ctrl_mul])
    z10 = execute_microcode(a_hi, b_lo, 0, [ctrl_mul])
    z11 = execute_microcode(a_hi, b_hi, 0, [ctrl_mul])

    # Accumulation: z00 + (z01+z10)<<16 + z11<<32
    mid = z01 + z10
    # Lower 32: z00[31:0] + mid[15:0]<<16
    lo_raw = z00 + ((mid & 0xFFFF) << 16)
    lo32 = lo_raw & 0xFFFFFFFF
    carry = lo_raw >> 32
    # Upper 32: z11[31:0] + mid[31:16] + carry from lo
    hi32 = (z11 + (mid >> 16) + carry) & 0xFFFFFFFF
    return lo32, hi32
def mulhi32x32(a, b):
    """Return upper 32 bits of 32×32→64 multiply."""
    _, hi = mul32x32(a, b)
    return hi
def sx64(x32):
    """Sign-extend 32-bit to Python signed 64-bit."""
    return x32 - 0x100000000 if (x32 & SMASK_32) else x32
def mul32_hw(a, b):
    r = arith4(a, b, 0, ArithMode.MUL32, 0)
    return r['res'], r['aux']
def mulhi_hw(a, b):
    r = arith4(a, b, 0, ArithMode.MULHI, 0)
    return r['res']
def mul32u_hw(a, b):
    r = arith4(a, b, 0, ArithMode.MUL32, 0, unsigned=True)
    return r['res'], r['aux']
def mulhiu_hw(a, b):
    r = arith4(a, b, 0, ArithMode.MULHI, 0, unsigned=True)
    return r['res']
def log2_micro(x):
    # Pass1: LZC
    ctrl_lzc = {'permb': {**_b_perm, 'prev_in_strobe': 8},
                'bitfrob': {**_b_bitf, 'mode_imm6': BitFrobMode.LZC, 'prev_in_strobe': 0},
                'ternlog': {**_b_tern, 'prev_in_strobe': 8},
                'arith4': {**_b_arit, 'prev_in_strobe': 8}}
    out = execute_pipeline(x, 0, 0, ctrl_lzc, 0, 0)
    # Pass2: 31 - LZC(x) = 31 + (-LZC). in_a=31, prev_in into src2 negated
    ctrl_sub = {'permb': {**_b_perm, 'prev_in_strobe': 8},
                'bitfrob': {**_b_bitf, 'prev_in_strobe': 8},
                'ternlog': {**_b_tern, 'prev_in_strobe': 8},
                'arith4': {**_b_arit, 'mode_imm6': ArithMode.ADD, 'inv_2': True,
                           'prev_in_strobe': 2, 'write_flags': True}}  # s1=31, s2=-prev_in, s3=0
    out2 = execute_pipeline(31, 0, 0, ctrl_sub, out['res'], 0)
    return out2['res']
def log10_micro(x):
    if x >= 1000000000: return 9
    if x >= 100000000: return 8
    if x >= 10000000: return 7
    if x >= 1000000: return 6
    if x >= 100000: return 5
    if x >= 10000: return 4
    if x >= 1000: return 3
    if x >= 100: return 2
    if x >= 10: return 1
    return 0
ctrl_mul32 = {
    'permb':  _b_perm, 'bitfrob': _b_bitf, 'ternlog': _b_tern,
    'arith4': {'mode_imm6': ArithMode.MUL32, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 0, 'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False}
}
ctrl_mul32acc = {
    'permb':  _b_perm, 'bitfrob': _b_bitf,
    'ternlog': {'tern_lut': TernLut.MOV_C, 'prev_in_strobe': 8,  # bypass res, aux=c
                'src3_idx': 0, 'cst_table': False, 'write_flags': False,
                'read_flags': False, 'internal_table': False},
    'arith4': {'mode_imm6': ArithMode.MUL32ACC, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 4,  # prev_in(lo1)→s3
                'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False}
}
FWD_MAP = [0x70, 0xD2, 0xAC, 0xA0, 0x73, 0x7A, 0xF0, 0xC8]
INV_MAP = [0x1A, 0x0B, 0x26, 0x2A, 0xA3, 0x49, 0xEB, 0x41]
GF4_POLY = 0x13
LAM = 0xC
def _gf4_mul(a, b):
    """GF(2^4) multiply via pipeline primitives: CLMUL_LO + POLY_RED mod 0x13."""
    r = bitfrob(a & 0xF, b & 0xF, 0, BitFrobMode.CLMUL_LO, 0)['res'] & 0xFF
    return bitfrob(r, 0, GF4_POLY, BitFrobMode.POLY_RED, 0)['res'] & 0xF
def _map_vec(x, rows):
    """Linear GF(2) map: each output bit = XOR of selected input bits (decoder-synthesized)."""
    r = 0
    for ob in range(8):
        d = 0
        for ib in range(8):
            if (rows[ob] >> ib) & 1 and (x >> ib) & 1:
                d ^= 1
        if d:
            r |= 1 << ob
    return r
def _composite_inv(v):
    """GF((2^4)^2) inverse: d = ah^2*lam + ah*al + al^2, then divide."""
    if v == 0:
        return 0
    ah, al = v & 0xF, v >> 4
    d = _gf4_mul(_gf4_mul(ah, ah), LAM) ^ _gf4_mul(ah, al) ^ _gf4_mul(al, al)
    # d_inv via NIBLKP (GF(2^4) inverse ROM in BITFROB_CST[32..47], index in s1)
    di = bitfrob(d, 0, 0, BitFrobMode.NIBLKP, 0)['res'] & 0xF
    return _gf4_mul(ah, di) | (_gf4_mul(ah ^ al, di) << 4)
def _composite_sbox(x):
    """Full AES S-box via composite-field path (all ops = pipeline primitives)."""
    v = _map_vec(x, FWD_MAP)          # GF(2^8) → GF(2^4)^2 (decoder XOR eqns)
    vi = _composite_inv(v)            # inverse in GF((2^4)^2): NIBLKP + gf4_mul
    y = _map_vec(vi, INV_MAP)         # GF(2^4)^2 → GF(2^8)
    r = bitfrob(y, 0, 0x63, BitFrobMode.GFNI_AFFINE, 0)['res'] & 0xFF  # affine
    return r
def _l_and(a, b): return ternlog(a, b, 0, TernLut.AND, 0)['res']
def _l_or(a, b):  return ternlog(a, b, 0, TernLut.OR, 0)['res']
def _l_xor(a, b): return ternlog(a, b, 0, TernLut.XOR, 0)['res']
def _l_not(a):    return ternlog(a, 0, 0, TernLut.NOT, 0)['res']
def pext32(x, m):
    """Full 32-bit pext via 5-stage butterfly (HD). CORRECT for ALL masks."""
    r = _l_and(x, m)                    # irrelevante Bits raus
    mk = shift_left(_l_not(m), 1)       # zaehle 0en rechts
    for i in range(5):
        k = 1 << i
        mp = _l_xor(mk, shift_left(mk, 1))      # Prefix-Broadcast
        mp = _l_xor(mp, shift_left(mp, 2))
        mp = _l_xor(mp, shift_left(mp, 4))
        mp = _l_xor(mp, shift_left(mp, 8))
        mp = _l_xor(mp, shift_left(mp, 16))
        mv = _l_and(mp, m)              # Bits die diese Stufe bewegen
        m = _l_or(_l_xor(m, mv), shift_right(mv, k))
        t = _l_and(r, mv)
        r = _l_or(_l_xor(r, t), shift_right(t, k))
        mk = _l_and(mk, _l_not(mp))
    return r
def pext_ref(x, m):
    res = 0; k = 0
    for i in range(32):
        if m & (1 << i):
            if x & (1 << i): res |= 1 << k
            k += 1
    return res
def pdep_ref(x, m):
    res = 0; k = 0
    for i in range(32):
        if m & (1 << i):
            if x & (1 << k): res |= 1 << i
            k += 1
    return res
def pdep32(x, m):
    """Full 32-bit pdep: INVERSE of pext butterfly. mv-Masken vorwaerts sammeln
    (m-Evolution haengt nur von m ab), dann x-Bits rueckwaerts nach OBEN bewegen.
    HW-Semantik: x wird auf die unteren popcount(m) Bits maskiert (POPCNT_B+PWADD
    Mikrocode), obere Bits ignoriert — so wie echte pdep-HW.
    rev32-Identitaet (pdep=rev(pext(rev x, rev m))) ist FALSCH: Reversal invertiert
    die Positions-Zuordnung nicht (verifiziert: 0x5678/0xF0F0F0F0 -> falsch)."""
    # popcount(m) via Pipeline: POPCNT_B + PWADD byte + PWADD word (3 Schritte)
    pc = bitfrob(m, 0, 0, BitFrobMode.POPCNT_B, 0)['res']
    pc = arith4(pc, 0, 0, ArithMode.PWADD, 0, op_type_1=OpType.BYTE)['res']
    pc = arith4(pc, 0, 0, ArithMode.PWADD, 0, op_type_1=OpType.WORD)['res']
    x = x & ((1 << pc) - 1) if pc else 0
    mvs = []
    mk = shift_left(_l_not(m), 1)
    mc = m
    for i in range(5):
        k = 1 << i
        mp = _l_xor(mk, shift_left(mk, 1))      # Prefix-Broadcast
        mp = _l_xor(mp, shift_left(mp, 2))
        mp = _l_xor(mp, shift_left(mp, 4))
        mp = _l_xor(mp, shift_left(mp, 8))
        mp = _l_xor(mp, shift_left(mp, 16))
        mv = _l_and(mp, mc)
        mvs.append((k, mv))
        mc = _l_or(_l_xor(mc, mv), shift_right(mv, k))
        mk = _l_and(mk, _l_not(mp))
    r = x & MASK_RLEN
    for k, mv in reversed(mvs):                 # Rueckwaerts expandieren
        t = _l_and(r, shift_right(mv, k))
        r = _l_or(_l_xor(r, t), shift_left(t, k))
    return r
