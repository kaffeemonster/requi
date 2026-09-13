#!/usr/bin/env python3
"""shell_algos.py — 4 Algorithmus-Tests gegen den ISA-Shell-Simulator.

Harness read-only: isa_shell.py / pipeline.py werden importiert, NIE editiert.
Jeder Test = eigene Funktion + assert + PASS/FAIL-Zeile. Exit 0 <=> alle PASS.

Encoding-Notizen (isa_shell.py):
  - dst global 5 Bit (C0-C15=0-15, S0-S15=16-31); src-Felder gruppenrelativ 4 Bit.
  - sarithi_w = F1 ADD-only (S-Gruppe, Imm13 signed); C-Imm gibt es nicht ->
    S->C-Transfer ueber RAM-Scratch.
  - CMP: res=0xFFFFFFFF (FLAG_S) wenn gleich, res=0 (FLAG_Z) wenn ungleich.
    bxx FLAG_S = "branch wenn gleich".
  - Offsets: PC-basiert, 2-Byte-Einheiten, offs = (target_pc - branch_pc) // 2.
"""
import sys

sys.path.insert(0, '/home/redbully/ecpu/requi/wayfinder/pipeline_ops')

from isa_shell import (
    ShellCPU, carith_w, sarith_w, sarithi_w, ctrl_w, mem_w, bitfrob_w, bxx_w,
    bxx_ne, bxx_eq, ternlog_w, ldi_movx_w, ldi_mask_w, slogii_w,
    cbitfrob_i_w,
)
from pipeline import ArithMode, BitFrobMode, TernLut, FLAG_S, OpType

CODE = 0x1080


def _halt():
    return ctrl_w(0, 0, 0, 0, scale=0, wrf=False)


# ---------------------------------------------------------------------------
# 1) memcpy: 16 Worte (64 B) 0x1100 -> 0x1400, ld.w/st.w (scale=2), S-Ptr,
#    S-Zaehler, CMP+bxx FLAG_S Exit bei 0.
# ---------------------------------------------------------------------------
def test_memcpy():
    S1, S2, S3 = 17, 18, 19          # src, dst, cnt (S-Gruppe)
    C1 = 1
    prog = [
        ldi_movx_w(S1, 0x1100),                    # S1 = 0x1100 (src)
        ldi_movx_w(S2, 0x1400),                    # S2 = 0x1400 (dst)
        sarithi_w(0x8, ArithMode.ADD, S3, 0, 16),  # S3 = 16 (cnt)
        # loop:
        mem_w(C1, 1, 0, 0, 2),                     # C1 = ld.w [S1]
        mem_w(C1, 2, 0, 0, 2, wrf=True),           # st.w [S2] = C1
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 4),   # S1 += 4
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 4),   # S2 += 4
        sarithi_w(0x8, ArithMode.ADD, S3, 3, -1, wrf=True),  # S3 -= 1, Flags(Z)
        bxx_ne(-10),                               # S3!=0 → loop (Z=0 feuert)
        _halt(),                                   # S3==0 → exit
    ]
    cpu = ShellCPU()
    src_words = [(0xCAFE0000 + i * 0x101) & 0xFFFFFFFF for i in range(16)]
    for i, w in enumerate(src_words):                   # 0x1100 == RAM-Offset 0x1100
        cpu.ram[0x1100 + 4 * i:0x1104 + 4 * i] = w.to_bytes(4, 'little')
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    dst = cpu.ram[0x1400:0x1440]                        # addr == RAM-Offset
    src = cpu.ram[0x1100:0x1140]
    exp = 3 + 16 * 6 + 1       # setup(3) + 16x loop-body(6) + halt
    ok = (n == exp and dst == src
          and cpu.op_counts.get('ld.2') == 16
          and cpu.op_counts.get('st.2') == 16
          and cpu.op_counts.get('bxx') == 16)
    print(f"[1] memcpy: 16 words 0x1100->0x1400 | instr={n} (exp {exp}), "
          f"ld.w={cpu.op_counts.get('ld.2')}, st.w={cpu.op_counts.get('st.2')}, "
          f"bxx={cpu.op_counts.get('bxx')}, dst==src={dst == src}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 2) strcpy: "copy me!"+NUL (10 B) 0x1100 -> 0x1500, ld.b/st.b (scale=0),
#    Exit bei geladenem Byte == 0 (CMP vs C0, bxx FLAG_S).
# ---------------------------------------------------------------------------
def test_strcpy():
    S1, S2 = 17, 18
    C1 = 1
    prog = [
        ldi_movx_w(S1, 0x1100),                    # S1 = 0x1100 (src)
        ldi_movx_w(S2, 0x1500),                    # S2 = 0x1500 (dst)
        # loop:
        mem_w(C1, 1, 0, 0, 0),                     # C1 = ld.b [S1]
        mem_w(C1, 2, 0, 0, 0, wrf=True),           # st.b [S2] = C1
        carith_w(ArithMode.CMP, 0, C1, 0, 0, wrf=True),  # cmp C1, C0: Z=1 wenn UNGLEICH (per-Lane-Maske)
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 1),   # S1 += 1
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 1),   # S2 += 1
        bxx_eq(-10),                               # byte!=0 (Z=1, ungleich) → loop; ==0 → exit
        _halt(),                                   # exit
    ]
    s = b"copy me!\x00"                                 # 9 Zeichen + NUL = 10 B
    cpu = ShellCPU()
    cpu.ram[0x1100:0x1100 + len(s)] = s                 # addr == RAM-Offset
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    dst = bytes(cpu.ram[0x1500:0x1500 + len(s)])        # addr == RAM-Offset
    n_nul = len(s)                                       # 9 iterationen (incl. NUL)
    exp = 2 + n_nul * 6 + 1          # setup(2) + loop(6 pro byte, incl. NUL) + halt
    ok = (n == exp and dst == s and cpu.read_dst(C1) == 0
          and cpu.op_counts.get('bxx') == n_nul)
    print(f"[2] strcpy: {len(s)} bytes 0x1100->0x1500 | instr={n} (exp {exp}), "
          f"dst==src={dst == s}, bxx={cpu.op_counts.get('bxx')}, "
          f"C1(byte nach loop)={cpu.read_dst(C1)}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 3) popcount: Maske 0x0F0F0F0F (16 gesetzte Bits) in C-Reg bauen (S-Gruppe
#    via sarithi+sshufb-shift+slogi-OR, S->C ueber RAM-Scratch), dann
#    bitfrob POPCNT_N (1 Instruktion, je-Nibble-Zaehler -> 0x04040404).
#    Voller Popcount = 16 via skalarer SWAR-Kette: POPCNT_N * 0x01010101
#    (MUL32) >> 24. (Pipeline-Notiz: voller Popcnt = POPCNT_B+PWADD x2
#    Mikrocode; Harness arith4 ist SCALAR-only -> SWAR-Ersatz.)
# ---------------------------------------------------------------------------
def test_popcount():
    C1, C2, C3 = 1, 2, 3
    prog = [
        ternlog_w(0xAA, C1, 0, 0, 4, cst=True),            # MOV_C + cst-Pool[4] -> C1=0x0F0F0F0F
        bitfrob_w(BitFrobMode.POPCNT_N, C2, C1, 0),        # C2 = je-Nibble-Popcnt = 0x04040404
        carith_w(ArithMode.PSAD, C3, C2, 0, 0, op_type=OpType.BYTE),  # C3 = Σ|Byte| = 16
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    mask = cpu.read_dst(C1)
    nib_cnt = cpu.read_dst(C2)
    full = cpu.read_dst(C3)                          # PSAD.b: horizontale Byte-Add
    ok = (n == len(prog) and mask == 0x0F0F0F0F
          and nib_cnt == 0x04040404
          and full == 16
          and cpu.op_counts.get('bitfrob:POPCNT_N') == 1
          and cpu.op_counts.get('ternlog') == 1
          and cpu.op_counts.get('carith:PSAD') == 1)
    print(f"[3] popcount 0x0F0F0F0F: mask=0x{mask:08x} (16 Bits), "
          f"POPCNT_N=0x{nib_cnt:08x} (je-Nibble, 1 Instruktion), "
          f"PSAD.b=0x{full:08x} ({full}, exp 16; horizontale Summe statt "
          f"MUL32+>>24)")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 4) Unaligned Word-Load: 0xDEADBEEF bei 0x1183 (addr == RAM-Offset, ungerade) schreiben,
#    ld.w via Basis S1=0x1180 + src2-Index 3 (byte-exakt, Harness byteweise).
# ---------------------------------------------------------------------------
def test_unaligned():
    S1, S2 = 17, 18
    C1 = 1
    prog = [
        ldi_movx_w(S1, 0x1180),                       # S1 = 0x1180 (ein LDI statt 2 sarithi)
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 3, shift=0),        # S2 = 3
        mem_w(C1, 1, 2, 0, 2),                          # C1 = ld.w [S1+S2]
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.ram[0x1183:0x1187] = (0xDEADBEEF).to_bytes(4, 'little')  # addr == RAM-Offset
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(C1)
    ok = (n == len(prog) and got == 0xDEADBEEF)
    print(f"[4] unaligned ld.w @0x1183 (base S1=0x1180 + idx 3): "
          f"got=0x{got:08x} (exp 0xDEADBEEF), instr={n}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok

# ---------------------------------------------------------------------------
# 5) strlen: "Hello, ISA World!"+NUL (18 B) auf 0x1100 (addr == RAM-Offset),
#    S1 = Pointer (via LDI 0x1100), Zaehler via S1-Referenz (exkl. NUL),
#    ld.b-loop, CMP+bxx_eq (Z=1 wenn ungleich, per-Lane-Maske).
# ---------------------------------------------------------------------------
def test_strlen():
    S1, S2 = 17, 18               # S1 = Pointer, S2 = Zaehler (S-Gruppe)
    C1 = 1                        # Byte-Puffer (C-Gruppe)
    s = b"Hello, ISA World!\x00"  # 15 Zeichen + NUL = 16 B
    cpu = ShellCPU()
    cpu.ram[0x1100:0x1100 + len(s)] = s    # addr == RAM-Offset
    prog = [
        ldi_movx_w(S1, 0x1100),                    # S1 = 0x1100 (LDI statt 2 sarithi)
        # loop:
        mem_w(C1, 1, 0, 0, 0),                     # C1 = ld.b [S1]
        carith_w(ArithMode.CMP, 0, C1, 0, 0, wrf=True),  # Z=1 wenn UNGLEICH (per-Lane)
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 1),   # S1 += 1
        bxx_eq(-6),                                # byte!=0 (Z=1) → loop; ==0 → exit
        _halt(),                                   # exit
    ]
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(S1) - 0x1100 - 1    # 15: "Hello, ISA World!" (exkl. NUL)
    exp = len(s) - 1                       # 15
    exp_instr = 1 + len(s) * 4 + 1          # ldi + lenx(ld,cmp,inc,bxx) + NUL-iter + halt
    ok = (n == exp_instr and got == exp and cpu.read_dst(C1) == 0)
    print(f"[5] strlen: {len(s)} B @0x1100 | S1+{got}=0x{0x1100+got:04x} (exp +{exp}), "
          f"instr={n} (exp {exp_instr}), C1(byte nach loop)={cpu.read_dst(C1)}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 6) FIR-Filter: 4 Taps coeff=[1,2,3,4] @0x1600, samples=[5,6,7,8] @0x1640,
#    MAC-Kette via MUL32ACC (C1 = C1 + C2*C3), S-Pointer-Paar + Zaehler.
#    exp: 1*5+2*6+3*7+4*8 = 70.
#    LDI-Basen + S3-Decrement-Z (wrf) -> Ein-Branch bxx_ne (kein CMP+bra).
# ---------------------------------------------------------------------------
def test_fir():
    S1, S2, S3 = 17, 18, 19
    C1, C2, C3 = 1, 2, 3
    prog = [
        ldi_movx_w(S1, 0x1600),                        # S1 = 0x1600 (coef)
        ldi_movx_w(S2, 0x1640),                        # S2 = 0x1640 (samp)
        ldi_movx_w(S3, 4),                             # S3 = 4 (cnt)
        ldi_movx_w(C1, 0),                             # C1 = 0 (acc)
        mem_w(C2, 1, 0, 0, 2),                    # loop: C2 = ld.w [S1]
        mem_w(C3, 2, 0, 0, 2),                    #       C3 = ld.w [S2]
        carith_w(ArithMode.MUL32ACC, C1, C2, C3, s3=C1),  #  C1 = C1 + C2*C3
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 4, shift=0),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 4, shift=0),
        sarithi_w(0x8, ArithMode.ADD, S3, 3, -1, shift=0, wrf=True),  # Z bei 0
        bxx_ne(-12),                                 # loop solange S3 != 0 (6 Woerter rauf)
        _halt(),
    ]
    cpu = ShellCPU()
    coef = [1, 2, 3, 4]
    samp = [5, 6, 7, 8]
    for i, v in enumerate(coef):                          # 0x1600 == RAM-Offset
        cpu.ram[0x1600 + 4 * i:0x1604 + 4 * i] = v.to_bytes(4, 'little')
    for i, v in enumerate(samp):                          # 0x1640 == RAM-Offset
        cpu.ram[0x1640 + 4 * i:0x1644 + 4 * i] = v.to_bytes(4, 'little')
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(C1)
    exp = 4 + 4 * 7 + 1     # setup + 4x loop(7, bxx zaehlt immer mit) + halt
    ok = (n == exp and got == 70
          and cpu.op_counts.get('carith:MUL32ACC') == 4)
    print(f"[6] FIR 4-tap: got={got} (exp 70), instr={n} (exp {exp}), "
          f"MUL32ACC={cpu.op_counts.get('carith:MUL32ACC')}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 7) GF(2^8)-Mul via CLMUL_LO/HI + POLY_RED(0x11B): p = hi<<8|lo, dann mod.
#    Referenz: Bit-fuer-Bit gf_mul (carryless + poly 0x11B inline).
#    Fälle: 0x80*0x02 -> 0x1B (zeigt echte Reduktion 0x100%0x11B),
#           0x0F*0x0F -> 0xE1 (trivial, kein Reduktions-Bit).
# ---------------------------------------------------------------------------
def test_gf_mul():
    S1, S2 = 17, 18
    C1, C2, C3, C4, C7, C8, C9, C10 = 1, 2, 3, 4, 7, 8, 9, 10

    def gf_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            b >>= 1
            a <<= 1
            if a & 0x100:
                a ^= 0x11B
        return p & 0xFF

    def build(a, b):
        cpu = ShellCPU()
        cpu.ram[0x1680] = a                               # addr == RAM-Offset
        cpu.ram[0x1681] = b                               # addr == RAM-Offset
        prog = [
            ldi_movx_w(S1, 0x1680),                        # S1 = 0x1680
            ldi_movx_w(S2, 0x1681),                        # S2 = 0x1681
            mem_w(C1, 1, 0, 0, 0),                        # C1 = ld.b a
            mem_w(C2, 2, 0, 0, 0),                        # C2 = ld.b b
            bitfrob_w(BitFrobMode.CLMUL_LO, C3, C1, C2),  # C3 = lo-Byte Produkt
            bitfrob_w(BitFrobMode.CLMUL_HI, C4, C1, C2),  # C4 = hi-Byte Produkt
            cbitfrob_i_w(BitFrobMode.LSL, C7, C4, 8),     # C7 = C4 << 8
            ternlog_w(TernLut.OR, C8, C7, C3, 0),         # C8 = p (16-bit)
            ldi_movx_w(C9, 0x011B),                           # C9 = 0x11B (poly)
            bitfrob_w(BitFrobMode.POLY_RED, C10, C8, 0, C9),
            _halt(),
        ]
        cpu.load_words(CODE, prog)
        n = cpu.run(prog, start=CODE)
        return cpu, n, cpu.read_dst(C8), cpu.read_dst(C10)

    cpu, n1, p1, r1 = build(0x80, 0x02)
    cpu2, n2, p2, r2 = build(0x0F, 0x0F)
    PFIX = 11  # len(prog)-1: run() zaehlt halt nicht mit
    ok1 = (p1 == 0x100 and r1 == gf_mul(0x80, 0x02) == 0x1B and n1 == PFIX)
    ok2 = (p2 == 0x55 and r2 == gf_mul(0x0F, 0x0F) == 0x55 and n2 == PFIX)
    print(f"[7] GF(2^8): 0x80*0x02 -> p=0x{p1:04x} r=0x{r1:02x} "
          f"(exp 0x0100/0x1B), 0x0F*0x0F -> p=0x{p2:04x} r=0x{r2:02x} "
          f"(exp 0x55/0x55), instr={n1}/{n2} (exp {PFIX})")
    print("    ->", "PASS" if ok1 and ok2 else "FAIL")
    return ok1 and ok2


# ---------------------------------------------------------------------------
# 8) Binomial C(10,5)=252 via iterative Multiplikation/Division-Kette:
#    val = val * (10-i+1) / i  fuer i=1..5.  numer=[10,9,8,7,6] @0x16A0,
#    denom=[1,2,3,4,5] @0x16C0. Zwischenwerte 10,45,120,210,252 (< 2^32).
# ---------------------------------------------------------------------------
def test_binomial():
    S1, S2, S3 = 17, 18, 19
    C1, C2, C3 = 1, 2, 3
    prog = [
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 234, shift=4),
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 128, shift=4),    # S1 = 0x16A0 (numer)
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 236, shift=4),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 128, shift=4),    # S2 = 0x16C0 (denom)
        sarithi_w(0x8, ArithMode.ADD, S3, 3, 5, shift=0),        # S3 = 5 (cnt)
        sarithi_w(0x8, ArithMode.ADD, C1, 0, 1, shift=0),        # C1 = 1 (val)
        mem_w(C2, 1, 0, 0, 2),                          # loop: C2 = ld.w numer
        mem_w(C3, 2, 0, 0, 2),                          #       C3 = ld.w denom
        carith_w(ArithMode.MUL32, C1, C1, C2),          #       C1 = C1*C2 (lo)
        carith_w(ArithMode.DIV, C1, C1, C3),            #       C1 = C1/C3
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 4, shift=0),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 4, shift=0),
        sarithi_w(0x8, ArithMode.ADD, S3, 3, -1, shift=0),
        sarith_w(0x0, ArithMode.CMP, 0, 3, 0, wrf=True),  # cmp S3, S0
        bxx_w(FLAG_S, FLAG_S, chan=1, pair=0, offs=4),    # bxx S -> exit
        ctrl_w(0, 0, 0, -18, scale=0, wrf=False),         # bra loop
        _halt(),                                          # exit
    ]
    cpu = ShellCPU()
    numer = [10, 9, 8, 7, 6]
    denom = [1, 2, 3, 4, 5]
    for i, v in enumerate(numer):                         # 0x16A0 == RAM-Offset
        cpu.ram[0x16A0 + 4 * i:0x16A4 + 4 * i] = v.to_bytes(4, 'little')
    for i, v in enumerate(denom):                         # 0x16C0 == RAM-Offset
        cpu.ram[0x16C0 + 4 * i:0x16C4 + 4 * i] = v.to_bytes(4, 'little')
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(C1)
    exp = 6 + 4 * 10 + 9 + 1     # setup + 4x voll-loop(10) + letzter Iter(9) + halt
    ok = (n == exp and got == 252
          and cpu.op_counts.get('carith:MUL32') == 5
          and cpu.op_counts.get('carith:DIV') == 5)
    print(f"[8] Binomial C(10,5): got={got} (exp 252), instr={n} (exp {exp}), "
          f"MUL32={cpu.op_counts.get('carith:MUL32')}, "
          f"DIV={cpu.op_counts.get('carith:DIV')}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


def test_ldi():
    """LDI-Plane (0x7): MOVX (zerofill/merge/hex/sext/inv) + MASK (Muster).
    Verifiziert LDI-v2-Encoding aus isa_vision.md Sektion 3."""
    C1, C2, C3, C4, C5, C6, C7, C8 = 1, 2, 3, 4, 5, 6, 7, 8
    prog = [
        ldi_movx_w(C1, 0x5678, hw=0),                # C1 = 0x00005678
        ldi_movx_w(C1, 0x1234, hw=1, wrf=True),      # C1 |= 0x12340000 = 0x12345678
        ldi_movx_w(C2, 0x8000, hw=0, sext=True),     # C2 = sign-ext = 0xFFFF8000
        ldi_movx_w(C3, 0x00FF, hw=0, inv=True),      # C3 = ~0x000000FF = 0xFFFFFF00
        ldi_mask_w(C4, ones=8, rep=1, rot=8),        # C4 = 0xFF00FF00 (16-Bit-Elem rot)
        ldi_mask_w(C5, ones=1, rep=4, rot=0),        # C5 = 0x55555555 (2-Bit-Elem 01 x16)
        ldi_mask_w(C6, ones=16, rep=0, rot=16),      # C6 = 0xFFFF0000 (32-Bit 16-Einsen rot)
        ldi_mask_w(C7, ones=16, rep=0, rot=16, inv=True),  # C7 = 0x0000FFFF
        ldi_mask_w(C8, ones=8, rep=1, rot=8, wrf=True),   # merge auf C8 (war 0) = 0xFF00FF00
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    ok = (n == len(prog)  # 9 LDI + halt (run zaehlt halt mit)
          and cpu.read_dst(C1) == 0x12345678
          and cpu.read_dst(C2) == 0xFFFF8000
          and cpu.read_dst(C3) == 0xFFFFFF00
          and cpu.read_dst(C4) == 0xFF00FF00
          and cpu.read_dst(C5) == 0x55555555
          and cpu.read_dst(C6) == 0xFFFF0000
          and cpu.read_dst(C7) == 0x0000FFFF
          and cpu.read_dst(C8) == 0xFF00FF00)
    print(f"[9] LDI: C1=0x{cpu.read_dst(C1):08x} C2=0x{cpu.read_dst(C2):08x} "
          f"C3=0x{cpu.read_dst(C3):08x} C4=0x{cpu.read_dst(C4):08x}")
    print(f"    C5=0x{cpu.read_dst(C5):08x} C6=0x{cpu.read_dst(C6):08x} "
          f"C7=0x{cpu.read_dst(C7):08x} C8=0x{cpu.read_dst(C8):08x}, instr={n}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


def test_slogii_tsti():
    """F1 slogii (0xA-0xF): Muster [ones|rep|rot] + AND/OR/XOR. tsti-Pseudo-Op:
    slogii WRF=1 + dst=zero -> Flags ohne Write. sarithi-F1: val<<shift."""
    S1, S2, S3, S4, S5 = 17, 18, 19, 20, 21
    prog = [
        # sarithi val<<shift: 0x800 = 1<<11, S1 = 4<<10 = 0x1000
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 4, shift=10),     # S1 = 0x1000
        slogii_w('and', S2, S1, ones=8, rep=1, rot=8),         # S2 = 0x1000 & 0xFF00FF00
        slogii_w('or',  S3, S1, ones=16, rep=0, rot=16),       # S3 = 0x1000 | 0xFFFF0000
        slogii_w('xor', S4, S1, ones=1, rep=4, rot=0),         # S4 = 0x1000 ^ 0x55555555
        slogii_w('and', 0,  S1, ones=8, rep=1, rot=8, wrf=True), # tsti: flags setzen
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    ok = (n == len(prog)
          and cpu.read_dst(S1) == 0x1000
          and cpu.read_dst(S2) == 0x1000 & 0xFF00FF00
          and cpu.read_dst(S3) == 0x1000 | 0xFFFF0000
          and cpu.read_dst(S4) == 0x1000 ^ 0x55555555)
    print(f"[10] slogii: S1=0x{cpu.read_dst(S1):08x} S2=0x{cpu.read_dst(S2):08x} "
          f"S3=0x{cpu.read_dst(S3):08x} S4=0x{cpu.read_dst(S4):08x} fl=0x{cpu.flags:x}, instr={n}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


def test_cbitfrob_i():
    """F2C cbitfrob_i (Plane 0x8, C-Gruppe): volle 0..31-Bit-Shifts via
    Spar-Core-Artefakt — amt<8 = 1 Passage (bitfrob), amt>=8 = 2 Passagen
    (permb-Byte-Grob + bitfrob-Fein, +1 Extra-Zyklus je grosse Shift).
    Werte = Referenz-32-Bit-Arithmetik (LSR/LSL/ASR/ROR/ROL)."""
    C1, C2, C3, C4, C5, C6, C7, C8, C9 = 1, 2, 3, 4, 5, 6, 7, 8, 9
    prog = [
        ldi_movx_w(C1, 0x5678, hw=0),                 # C1 = 0x12345678
        ldi_movx_w(C1, 0x1234, hw=1, wrf=True),
        cbitfrob_i_w(BitFrobMode.LSR, C2, C1, 12),    # C2 = C1 >> 12
        cbitfrob_i_w(BitFrobMode.LSL, C3, C1, 12),    # C3 = C1 << 12
        cbitfrob_i_w(BitFrobMode.ASR, C4, C1, 8),     # C4 = C1 >> 8 arith
        ldi_movx_w(C5, 0x8000, hw=1),                 # C5 = 0x80000000
        cbitfrob_i_w(BitFrobMode.ASR, C6, C5, 12),    # C6 = 0x80000000>>12 ar
        cbitfrob_i_w(BitFrobMode.ROR, C7, C1, 20),    # C7 = ROR20
        cbitfrob_i_w(BitFrobMode.ROL, C8, C1, 12),    # C8 = ROL12
        cbitfrob_i_w(BitFrobMode.LSR, C9, C1, 3),     # C9 = small (amt<8)
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    exp_shift = 0  # alle Shifts = 1 Passage (Grob+Fein in derselben Passage)
    ok = (n == len(prog) and cpu.cycle == n + exp_shift
          and cpu.read_dst(C2) == 0x12345678 >> 12
          and cpu.read_dst(C3) == (0x12345678 << 12) & 0xFFFFFFFF
          and cpu.read_dst(C4) == 0x12345678 >> 8
          and cpu.read_dst(C6) == 0xFFF80000
          and cpu.read_dst(C7) == 0x45678123
          and cpu.read_dst(C8) == 0x45678123
          and cpu.read_dst(C9) == 0x02468ACF)
    print(f"[11] cbitfrob_i: LSR12=0x{cpu.read_dst(C2):08x} "
          f"LSL12=0x{cpu.read_dst(C3):08x} ASR8=0x{cpu.read_dst(C4):08x}")
    print(f"     ASR12(0x80000000)=0x{cpu.read_dst(C6):08x} "
          f"ROR20=0x{cpu.read_dst(C7):08x} ROL12=0x{cpu.read_dst(C8):08x} "
          f"LSR3=0x{cpu.read_dst(C9):08x}, instr={n} cycle={cpu.cycle} "
          f"(exp {n}+{exp_shift})")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


def main():
    tests = [test_memcpy, test_strcpy, test_popcount, test_unaligned, test_strlen,
             test_fir, test_gf_mul, test_binomial, test_ldi, test_slogii_tsti,
             test_cbitfrob_i]
    results = []
    for t in tests:
        try:
            results.append(t())
        except Exception as e:                          # Harness/Assert-Fehler
            import traceback
            traceback.print_exc()
            print(f"    {t.__name__}: EXCEPTION -> FAIL")
            results.append(False)
    all_ok = all(results)
    print("=" * 60)
    print("ALL TESTS:", "PASS" if all_ok else "FAIL")
    sys.exit(0 if all_ok else 1)


if __name__ == '__main__':
    main()
