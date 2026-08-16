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
    ShellCPU, carith_w, sarith_w, sarithi_w, ctrl_w, mem_w, bitfrob_w,
)
from pipeline import ArithMode, BitFrobMode, FLAG_S

CODE = 0x1080


def _halt():
    return ctrl_w(0, 0, 0, 0, scale=0, wrf=False)


# ---------------------------------------------------------------------------
# 1) memcpy: 16 Worte (64 B) 0x1100 -> 0x1400, ld.w/st.w (scale=2), S-Ptr,
#    S-Zaehler, CMP+bxx FLAG_S Exit bei 0.
# ---------------------------------------------------------------------------
def test_memcpy():
    S1, S2, S3 = 17, 18, 19          # dst global 5 Bit (S1=17...)
    C1 = 1
    prog = [
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 0x900),    # S1 = 0x1100 (src)
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 0xC00),    # S2 = 0x1400 (dst)
        sarithi_w(0x8, ArithMode.ADD, S3, 0, 16),       # S3 = 16 (cnt)
        mem_w(C1, 1, 0, 0, 2),                          # loop: C1 = ld.w [S1]
        mem_w(C1, 2, 0, 0, 2, wrf=True),                #       st.w [S2] = C1
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 4),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 4),
        sarithi_w(0x8, ArithMode.ADD, S3, 3, -1),       # S3 -= 1
        sarith_w(0x0, ArithMode.CMP, 0, 3, 0, wrf=True),  # cmp S3, S0
        ctrl_w(FLAG_S, 0, 0, 4, scale=0, wrf=True),     # bxx S -> exit (i13)
        ctrl_w(0, 0, 0, -14, scale=0, wrf=False),       # bra loop (i5)
        _halt(),                                        # exit
    ]
    cpu = ShellCPU()
    src_words = [(0xCAFE0000 + i * 0x101) & 0xFFFFFFFF for i in range(16)]
    for i, w in enumerate(src_words):                   # 0x1100 = off 0x100
        cpu.ram[0x100 + 4 * i:0x104 + 4 * i] = w.to_bytes(4, 'little')
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    dst = cpu.ram[0x400:0x440]                          # 0x1400 = off 0x400
    src = cpu.ram[0x100:0x140]
    exp = 5 + 15 * 8 + 7 + 1        # setup+15xvoll-loop+bxx-taken(7)+halt
    ok = (n == exp and dst == src
          and cpu.op_counts.get('ld.2') == 16
          and cpu.op_counts.get('st.2') == 16)
    print(f"[1] memcpy: 16 words 0x1100->0x1400 | instr={n} (exp {exp}), "
          f"ld.w={cpu.op_counts.get('ld.2')}, st.w={cpu.op_counts.get('st.2')}, "
          f"dst==src={dst == src}")
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
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 0x900),    # S1 = 0x1100 (src)
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 0xD00),    # S2 = 0x1500 (dst)
        mem_w(C1, 1, 0, 0, 0),                          # loop: C1 = ld.b [S1]
        mem_w(C1, 2, 0, 0, 0, wrf=True),                #       st.b [S2] = C1
        carith_w(ArithMode.CMP, 0, C1, 0, 0, wrf=True), #       cmp C1, C0
        ctrl_w(FLAG_S, 0, 0, 8, scale=0, wrf=True),     #       bxx S -> exit
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 1),
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 1),
        ctrl_w(0, 0, 0, -12, scale=0, wrf=False),       # bra loop (i4)
        _halt(),                                        # exit
    ]
    s = b"copy me!\x00"                                 # 9 Zeichen + NUL = 10 B
    cpu = ShellCPU()
    cpu.ram[0x100:0x100 + len(s)] = s                   # 0x1100 = off 0x100
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    dst = bytes(cpu.ram[0x500:0x500 + len(s)])          # 0x1500 = off 0x500
    exp = 4 + (len(s) - 1) * 7 + 4 + 1   # setup+NUL-iter(4)+halt
    ok = (n == exp and dst == s and cpu.read_dst(C1) == 0)
    print(f"[2] strcpy: {len(s)} bytes 0x1100->0x1500 | instr={n} (exp {exp}), "
          f"dst==src={dst == s}, C1(byte nach loop)={cpu.read_dst(C1)}")
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
    S1, S2, S3, S4, S5, S6, S7 = 17, 18, 19, 20, 21, 22, 23
    C1, C2, C3, C4 = 1, 2, 3, 4
    prog = [
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 15),       # S1 = 0x0F
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 8),        # S2 = 8 (shift amt)
        sarith_w(0x6, 3, S2, 1, 2),                     # S2 = S1 << 8 = 0x0F00
        sarith_w(0x2, 0xE, S1, 1, 2),                   # S1 |= S2 = 0x0F0F
        sarithi_w(0x8, ArithMode.ADD, S3, 0, 16),       # S3 = 16 (shift amt)
        sarith_w(0x6, 3, S3, 1, 3),                     # S3 = S1 << 16
        sarith_w(0x2, 0xE, S1, 1, 3),                   # S1 |= S3 = 0x0F0F0F0F
        sarithi_w(0x8, ArithMode.ADD, S5, 0, 257),      # S5 = 0x101
        sarithi_w(0x8, ArithMode.ADD, S6, 0, 16),
        sarith_w(0x6, 3, S6, 5, 6),                     # S6 = S5 << 16
        sarith_w(0x2, 0xE, S5, 5, 6),                   # S5 |= S6 = 0x01010101
        sarithi_w(0x8, ArithMode.ADD, S4, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S4, 4, 0x980),    # S4 = 0x1180 (scratch)
        mem_w(S1, 4, 0, 0, 2, wrf=True),                # [S4] = S1 (mask)
        mem_w(C1, 4, 0, 0, 2),                          # C1 = mask
        bitfrob_w(BitFrobMode.POPCNT_N, C2, C1, 0),     # C2 = je-Nibble-Popcnt
        mem_w(S5, 4, 0, 0, 2, wrf=True),                # [S4] = 0x01010101
        mem_w(C3, 4, 0, 0, 2),                          # C3 = 0x01010101
        carith_w(ArithMode.MUL32, C4, C2, C3),          # C4 = lo32(C2*C3)
        mem_w(C4, 4, 0, 0, 2, wrf=True),                # [S4] = C4
        sarithi_w(0x8, ArithMode.ADD, S3, 0, 24),       # S3 = 24 (shift amt)
        mem_w(S7, 4, 0, 0, 2),                          # S7 = lo32-Produkt
        sarith_w(0x6, 2, S7, 7, 3),                     # S7 = S7 >> 24 = 16
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    mask = cpu.read_dst(C1)
    nib_cnt = cpu.read_dst(C2)
    full = cpu.read_dst(S7)
    exp_lo = (0x04040404 * 0x01010101) & 0xFFFFFFFF
    ok = (n == len(prog) and mask == 0x0F0F0F0F
          and nib_cnt == 0x04040404
          and (exp_lo >> 24) == 16 and full == 16
          and cpu.op_counts.get('bitfrob:POPCNT_N') == 1)
    print(f"[3] popcount 0x0F0F0F0F: mask=0x{mask:08x} (16 Bits), "
          f"POPCNT_N=0x{nib_cnt:08x} (je-Nibble, 1 Instruktion), "
          f"full popcount={full} (exp 16), lo32(0x04040404*0x01010101)"
          f"=0x{exp_lo:08x} (exp_lo>>24=16)")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


# ---------------------------------------------------------------------------
# 4) Unaligned Word-Load: 0xDEADBEEF bei 0x1183 (off 0x183, ungerade) schreiben,
#    ld.w via Basis S1=0x1180 + src2-Index 3 (byte-exakt, Harness byteweise).
# ---------------------------------------------------------------------------
def test_unaligned():
    S1, S2 = 17, 18
    C1 = 1
    prog = [
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 0x800),
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 0x980),    # S1 = 0x1180
        sarithi_w(0x8, ArithMode.ADD, S2, 0, 3),        # S2 = 3
        mem_w(C1, 1, 2, 0, 2),                          # C1 = ld.w [S1+S2]
        _halt(),
    ]
    cpu = ShellCPU()
    cpu.ram[0x183:0x187] = (0xDEADBEEF).to_bytes(4, 'little')
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(C1)
    ok = (n == len(prog) and got == 0xDEADBEEF)
    print(f"[4] unaligned ld.w @0x1183 (base S1=0x1180 + idx 3): "
          f"got=0x{got:08x} (exp 0xDEADBEEF), instr={n}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok

# ---------------------------------------------------------------------------
# 5) strlen: "Hello, ISA World!"+NUL (16 B) auf 0x1100 (RAM-off 0x100),
#    S1 = Pointer (via 2 ADD, Imm13-Limit: 0x800+0x900), S2 = Zaehler,
#    ld.b-loop, CMP+bxx FLAG_S Exit bei 0x00, Pointer+Zaehler incrementieren.
# ---------------------------------------------------------------------------
def test_strlen():
    S1, S2 = 17, 18               # S1 = Pointer, S2 = Zaehler (S-Gruppe)
    C1 = 1                        # Byte-Puffer (C-Gruppe)
    s = b"Hello, ISA World!\x00"  # 15 Zeichen + NUL = 16 B
    cpu = ShellCPU()
    cpu.ram[0x100:0x100 + len(s)] = s    # mem_addr 0x1100 = RAM-off 0x100
    prog = [
        sarithi_w(0x8, ArithMode.ADD, S1, 0, 0x800),   # S1 = S0(0) + 0x800 = 0x800
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 0x900),   # S1 = S1(0x800) + 0x900 = 0x1100
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 0),       # S2 = S2(0) + 0 = 0
        mem_w(C1, 1, 0, 0, 0),                         # loop: C1 = ld.b [S1]
        carith_w(ArithMode.CMP, 0, C1, 0, 0, wrf=True),#       CMP C1, C0
        ctrl_w(FLAG_S, 0, 0, 8, scale=0, wrf=True),    #       bxx S -> exit (i5)
        sarithi_w(0x8, ArithMode.ADD, S2, 2, 1),       #       S2 += 1
        sarithi_w(0x8, ArithMode.ADD, S1, 1, 1),       #       S1 += 1
        ctrl_w(0, 0, 0, -10, scale=0, wrf=False),      #       bra loop (i3)
        _halt(),                                       # exit
    ]
    cpu.load_words(CODE, prog)
    n = cpu.run(prog, start=CODE)
    got = cpu.read_dst(S2)
    exp = len(s) - 1                # 15: "Hello, ISA World!"
    exp_instr = 3 + (len(s) - 1) * 6 + 3 + 1   # setup + 15xvoll-loop + NUL-iter + halt
    ok = (n == exp_instr and got == exp and cpu.read_dst(C1) == 0)
    print(f"[5] strlen: {len(s)} B @0x1100 | S2={got} (exp {exp}), "
          f"instr={n} (exp {exp_instr}), C1(byte nach loop)={cpu.read_dst(C1)}")
    print("    ->", "PASS" if ok else "FAIL")
    return ok


def main():
    tests = [test_memcpy, test_strcpy, test_popcount, test_unaligned, test_strlen]
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
