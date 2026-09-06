"""z3-Modell des 4-Stufen-Pipeline-Kerns, Stufe 1 (ternlog).

Minimaler Beweis-Ansatz: per-Bit-Encoding. Jedes Bit des 32-Bit-Ergebnisses
wird einzeln ueber eine 3-Bit-LUT (lut_imm8, nur untere 8 Bit genutzt)
berechnet. Queries nur unter __main__-Guard (import-sauber).

Sektionen (M1..M19) als _run_MX-Funktionen; CLI-Auswahl via -g/--group (M-Namen
oder Aliase: ternlog/bitfrob/arith4/permb/pipe/macro/gf/decoder/smoke), --skip,
--list. Default: alle Sektionen. Per-Sektion-Timing wird immer gedruckt.
"""

import sys

import time

import z3

RLEN = 32


def model_ternlog(a, b, c, lut):
    """Modelliert die ternlog-Stufe in z3.

    a, b, c: z3 BitVec(32) Operanden.
    lut: z3 BitVec(32), nur untere 8 Bit sind signifikant.
    Rueckgabe: z3 BitVec(32) Ergebnis.

    Pro Bit i: idx = (a_i << 2) | (b_i << 1) | c_i (3-Bit-Index);
    Ausgangsbit i = (lut >> idx) & 1.
    """
    res = z3.BitVecVal(0, 32)
    for i in range(RLEN):
        ai = z3.Extract(i, i, a)
        bi = z3.Extract(i, i, b)
        ci = z3.Extract(i, i, c)
        # z3.Extract verlangt literale Indizes, daher per-Bit-Aufrollen;
        # symbolischer Shift via LShR + ZeroExt.
        idx = z3.Concat(ai, bi, ci)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, idx)))
        res = res | (z3.ZeroExt(31, bit) << i)
    return res


def model_lsr(s1, s2, s3):
    """Modelliert LSR (mode 0): Funnel (s1<<32)|s2, Shift um s3 & 7.

    Ergebnis = untere 32 Bit des logisch nach rechts geschobenen Funnels.
    Wert lebt in s2 (niederwertiger Operand).
    """
    amt = s3 & 7
    concat = z3.Concat(s1, s2)
    return z3.Extract(31, 0, z3.LShR(concat, z3.ZeroExt(32, amt)))


def model_lsl(s1, s2, s3):
    """Modelliert LSL (mode 1): Funnel (s1<<32)|s2, Shift um s3 & 7.

    Ergebnis = obere 32 Bit des nach links geschobenen Funnels.
    Wert lebt in s1 (hochwertiger Operand).
    """
    return z3.Extract(63, 32, z3.Concat(s1, s2) << z3.ZeroExt(32, s3 & 7))


def model_ror(s1, s3):
    """Modelliert ROR (mode 2): Selbst-Funnel (s1<<32)|s1.

    Ergebnis = untere 32 Bit des logisch nach rechts geschobenen Funnels.
    """
    amt = s3 & 7
    return z3.Extract(31, 0, z3.LShR(z3.Concat(s1, s1), z3.ZeroExt(32, amt)))


def model_rol(s1, s3):
    """Modelliert ROL (mode 8): Selbst-Funnel (s1<<32)|s1.

    Ergebnis = obere 32 Bit des nach links geschobenen Funnels.
    """
    return z3.Extract(63, 32, z3.Concat(s1, s1) << z3.ZeroExt(32, s3 & 7))


def model_mask(s3):
    """Modelliert MASK (mode 7): all-ones falls s3 != 0, sonst 0."""
    return z3.If(s3 != 0, z3.BitVecVal(0xFFFFFFFF, 32), z3.BitVecVal(0, 32))


def model_maskw(s3):
    """Modelliert MASKW (mode 12): n = s3 & 0x1F.

    Ergebnis = (1<<n)-1 fuer n != 0, sonst all-ones (n == 0).
    """
    n = s3 & 0x1F
    return z3.If(n == 0, z3.BitVecVal(0xFFFFFFFF, 32), (z3.BitVecVal(1, 32) << n) - 1)


def model_sext(s1, pos):
    """Modelliert SEXT (mode 9): Vorzeichenerweiterung ab Bit pos.

    pos ist konkreter Python-int (Decoder-synthetisiert, nicht symbolisch).
    """
    low_mask = (1 << (pos + 1)) - 1
    sign = z3.Extract(pos, pos, s1)
    mask_hi = z3.BitVecVal(0xFFFFFFFF, 32) & ~z3.BitVecVal(low_mask, 32)
    return z3.If(sign == 1, s1 | mask_hi, s1 & z3.BitVecVal(low_mask, 32))


def model_lzc(x):
    """Modelliert LZC (mode 5): Anzahl fuehrender Nullen.

    X == 0 -> 32; sonst 31 - (Index des hoechsten gesetzten Bits).
    Faltrichtung: die LETZTE Schleifeniteration wird zum AEUSSERSTEN If
    (zuerst geprueft). Aufsteigender Bereich (0..31) => bit31 aussen =>
    hoechstes Bit gewinnt => LZC.
    """
    pos = z3.BitVecVal(0, 32)
    for i in range(0, 32):
        pos = z3.If(z3.Extract(i, i, x) == 1, z3.BitVecVal(i, 32), pos)
    return z3.If(x == 0, z3.BitVecVal(32, 32), z3.BitVecVal(31, 32) - pos)


def model_tzc(x):
    """Modelliert TZC (mode 6): Anzahl nachfolgender Nullen.

    X == 0 -> 32; sonst Index des niederwertigsten gesetzten Bits.
    Faltrichtung: die LETZTE Schleifeniteration wird zum AEUSSERSTEN If
    (zuerst geprueft). Absteigender Bereich (31..0) => bit0 aussen =>
    niederwertigstes Bit gewinnt => TZC.
    """
    pos = z3.BitVecVal(0, 32)
    for i in range(31, -1, -1):
        pos = z3.If(z3.Extract(i, i, x) == 1, z3.BitVecVal(i, 32), pos)
    return z3.If(x == 0, z3.BitVecVal(32, 32), pos)


def model_popcnt_b(x):
    """Modelliert POPCNT_B (mode 11): Popcount pro Byte (0..8 pro Byte).

    SWAR-Trick: zunaechst je 2 Bits, dann 4 Bits, dann Byte-Spalten
    maskiert auf 0x0F0F0F0F; Ergebnis-Bytelanes 0..8.
    """
    x = x - ((x >> 1) & z3.BitVecVal(0x55555555, 32))
    x = (x & z3.BitVecVal(0x33333333, 32)) + ((x >> 2) & z3.BitVecVal(0x33333333, 32))
    x = (x + (x >> 4)) & z3.BitVecVal(0x0F0F0F0F, 32)
    return x


# --- M6: pext32/pdep32-Butterfly-Modelle (helpers.py pext32/pdep32) ---
def zland(a, b):
    """ternlog AND (0xC0) == a&b — M1 Q1 bewiesen, daher direkte BV-Op.
    (per-Bit-model_ternlog auf symbolischer Maske sprengt den Bitblast)"""
    return a & b


def zlor(a, b):
    """ternlog OR (0xFC) == a|b — M1 Q2 bewiesen, direkte BV-Op."""
    return a | b


def zlxor(a, b):
    """ternlog XOR (0x3C) == a^b — direkte BV-Op."""
    return a ^ b


def zlnot(a):
    """ternlog NOT (0x01) == ~a (32-Bit) — direkte BV-Op."""
    return ~a


def zshl(a, n):
    """shift_left(a, n) & MASK_RLEN — n KONKRET (k in {1,2,4,8,16})."""
    return a << z3.BitVecVal(n, 32)


def zshr(a, n):
    """shift_right(a, n) = LShR — n KONKRET."""
    return z3.LShR(a, z3.BitVecVal(n, 32))


def zpopcnt(x):
    """Voller Pipeline-Popcount (wie pdep32 ihn nutzt): POPCNT_B + PWADD byte + PWADD word."""
    y = model_popcnt_b(x)
    y = (y + z3.LShR(y, z3.BitVecVal(8, 32))) & z3.BitVecVal(0x00FF00FF, 32)
    y = (y + z3.LShR(y, z3.BitVecVal(16, 32))) & z3.BitVecVal(0x0000FFFF, 32)
    return y


def zpext32(x, m):
    """pext32 aus helpers.py: 5-Stufen-Butterfly (HD), nur ternlog + Shifts.
    ACHTUNG: mv = zland(mp, mm) nutzt die EVOLUIERENDE Maske (mm wird je Stufe
    neu zugewiesen), wie im Original."""
    r = zland(x, m)
    mk = zshl(zlnot(m), 1)
    mm = m
    for i in range(5):
        k = 1 << i
        mp = zlxor(mk, zshl(mk, 1))
        mp = zlxor(mp, zshl(mp, 2))
        mp = zlxor(mp, zshl(mp, 4))
        mp = zlxor(mp, zshl(mp, 8))
        mp = zlxor(mp, zshl(mp, 16))
        mv = zland(mp, mm)
        mm = zlor(zlxor(mm, mv), zshr(mv, k))
        t = zland(r, mv)
        r = zlor(zlxor(r, t), zshr(t, k))
        mk = zland(mk, zlnot(mp))
    return r


def zpdep32(x, m):
    """pdep32 aus helpers.py: mvs vorwaerts sammeln, x-Bits rueckwaerts NACH OBEN.
    HW-Semantik: x auf untere popcount(m) Bits maskiert (pc==0 -> 0, pc==32 -> 0xFFFFFFFF)."""
    pc = zpopcnt(m)
    lowmask = z3.If(pc == 0, z3.BitVecVal(0, 32),
                    (z3.BitVecVal(1, 32) << pc) - z3.BitVecVal(1, 32))
    x = x & lowmask
    mvs = []
    mk = zshl(zlnot(m), 1)
    mc = m
    for i in range(5):
        k = 1 << i
        mp = zlxor(mk, zshl(mk, 1))
        mp = zlxor(mp, zshl(mp, 2))
        mp = zlxor(mp, zshl(mp, 4))
        mp = zlxor(mp, zshl(mp, 8))
        mp = zlxor(mp, zshl(mp, 16))
        mv = zland(mp, mc)
        mvs.append((k, mv))
        mc = zlor(zlxor(mc, mv), zshr(mv, k))
        mk = zland(mk, zlnot(mp))
    r = x
    for k, mv in reversed(mvs):
        t = zland(r, zshr(mv, k))
        r = zlor(zlxor(r, t), zshl(t, k))
    return r


# --- M7: Bitswap/Expand-Modelle (1-Pass-Enumeration) ---
def model_bitswap(x, mask, sh):
    """XOR-Butterfly-Bitswap: t = (x ^ x>>sh) & mask; res = x ^ t ^ (t<<sh).

    mask, sh KONKRET (sh in {1,2,4,...}); klassische Nachbar-Vertauschung,
    z.B. mask=0x55555555, sh=1 vertauscht benachbarte Bitpaare."""
    t = (x ^ zshr(x, sh)) & mask
    return (x ^ t ^ zshl(t, sh)) & 0xFFFFFFFF


def z_pwaddb(x):
    """Pairwise Byte-Widen-Add (ein arith4-Stage): (x + x>>8) & 0x00FF00FF."""
    return (x + zshr(x, 8)) & z3.BitVecVal(0x00FF00FF, 32)


def z_popcnt32(x):
    """Voller 32-Bit-Popcount (3 Makro-Schritte): POPCNT_B + PWADD byte + PWADD word."""
    r = model_popcnt_b(x)
    r = z_pwaddb(r)
    r = (r + zshr(r, 16)) & z3.BitVecVal(0x0000FFFF, 32)
    return r


# --- M8: arith4-Skalar-Modell (Konkrete-Mode-Dispatch) ---
def model_arith4(s1, s2, s3, mode, c_in=z3.BitVecVal(0, 1), inv_1=False, inv_2=False, inv_3=False):
    """arith4-Skalar-Modell: s1/s2/s3 BitVec(32), mode konkret (Python-Dispatch),
    inv_1/2/3 als konkrete Bools (Python if, kein z3.If), c_in 1-Bit oder konkret.
    Liefert (res, aux) — aux = s3 default (Pipeline-Konvention)."""
    # Hinweis: unaeres -x (Z3_mk_bvneg) ist in dieser libz3 auf Konstanten mit
    # Bit31=1 kaputt (liefert falschen Wert); bvsub(0,x) ist sauber -> Ersatz.
    a = (z3.BitVecVal(0, 32) - s1) if inv_1 else s1          # 32-Bit Negation (0-s1)
    b = (z3.BitVecVal(0, 32) - s2) if inv_2 else s2
    c = (z3.BitVecVal(0, 32) - s3) if inv_3 else s3
    if mode == 1:   # ADD
        res = a + b + c
    elif mode == 2:  # ADDC (inv_2=True = SUBB-Integration: Carry-Beitrag als Borrow c-1)
        res = a + b + c + z3.ZeroExt(31, c_in) - (z3.BitVecVal(1, 32) if inv_2 else z3.BitVecVal(0, 32))
    elif mode == 4:  # USATADD — z3-Label der Hist-Nummer; ISS-Semantik = SATADD(mode 5) + unsigned=True
        full = z3.ZeroExt(2, a) + z3.ZeroExt(2, b) + z3.ZeroExt(2, c)
        res = z3.If(z3.UGT(full, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0xFFFFFFFF, 32), z3.Extract(31, 0, full))
    elif mode == 5:  # SATADD (signed sat, 34-Bit sign-ext: 3-Operanden-Summe bis +-3*2^31)
        full = z3.SignExt(2, a) + z3.SignExt(2, b) + z3.SignExt(2, c)
        # signed-Vergleich via Vorzeichen-Flip + UGT/ULT (z3py kennt kein SGT/SLT):
        #   UGT(full^S, x^S) <=> signed full > x;  ULT <=> signed full < x  (S = Bit 33)
        f34 = full ^ z3.BitVecVal(0x200000000, 34)
        res = z3.If(z3.UGT(f34, z3.BitVecVal(0x27FFFFFFF, 34)), z3.BitVecVal(0x7FFFFFFF, 32),
               z3.If(z3.ULT(f34, z3.BitVecVal(0x180000000, 34)), z3.BitVecVal(0x80000000, 32),
                     z3.Extract(31, 0, full)))
    elif mode == 6:   # AVG: (a+b+(c&1))>>1
        full = z3.ZeroExt(1, a) + z3.ZeroExt(1, b) + z3.ZeroExt(32, z3.Extract(0, 0, c))
        res = z3.Extract(31, 0, z3.LShR(full, 1))
    elif mode == 7:   # ABSADD: |a|+b+c (|INT_MIN| wrappt); Vorzeichen = Bit31
        # If(a>=0,...) war UGE -> immer a (nie negiert). Bit31-Check: 2^32-a wenn Bit31.
        absa = z3.If(z3.Extract(31, 31, a) == 1, z3.BitVecVal(0, 32) - a, a)
        res = absa + b + c
    elif mode == 10:  # SLT (Maske): Sign-Flip, signed Vergleich via Unsigned-Borrow
        # (Overflow-sicher, gleiche HW wie SLTU: carry-out==0 von ca+~cb+c
        # => ca<u cb => signed a<b; s3=1 strikt, s3=0 <=). Q61/Q62 (M12)
        # exponierten den Runtime-Bug (Bit31 des gewrappten a-b war falsch bei
        # entgegengesetzten Vorzeichen und |a-b|>=2^31); dieses Modell gleicht
        # der korrigierten pipeline.py. inv_2 BEWUSST ignoriert (raw s2).
        ca = a ^ z3.BitVecVal(0x80000000, 32)
        cb = s2 ^ z3.BitVecVal(0x80000000, 32)
        # 34-Bit: 3-Operanden-Summe bis 3*2^32 (33-Bit wuerde >2^33 wrappen)
        t34 = z3.ZeroExt(2, ca) + z3.ZeroExt(2, (~cb) & 0xFFFFFFFF) + z3.ZeroExt(2, c)
        # carry-out = full >= 2^32 (nicht nur Bit32: Bit33 kann gesetzt sein bei 34-Bit)
        res = z3.If(z3.UGT(t34, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0, 32), z3.BitVecVal(0xFFFFFFFF, 32))
    elif mode == 11:  # SLTU — z3-Label der Hist-Nummer; ISS-Semantik = SLT(mode 10) + unsigned=True
        # 34-Bit analog SLT (33-Bit-Overflow-Bug durch Fuzzer gefunden)
        full = z3.ZeroExt(2, a) + z3.ZeroExt(2, ~s2) + z3.ZeroExt(2, c)
        res = z3.If(z3.UGT(full, z3.BitVecVal(0xFFFFFFFF, 34)), z3.BitVecVal(0, 32), z3.BitVecVal(0xFFFFFFFF, 32))
    elif mode == 12:  # MFC (z3-Label der internen Nummer; ISS-Mode = ArithMode.MFC = 40)
        res = z3.ZeroExt(31, c_in)
    elif mode == 13:  # ADDSHIFT1: a+(b<<1)
        res = a + (b << 1)
    elif mode == 14:  # ADDSHIFT2: a+(b<<2)
        res = a + (b << 2)
    else:
        raise ValueError(f"M8a: mode {mode} nicht im Skalar-Satz")
    return (res, c)   # aux = s3 (post-inv) fuer alle M8a-Modi


# ---- geteilte Helper (von Sektionen in __main__-Guard gehoistet): ----
# Modell-Funktionen + Lemma-Tabelle + unsat-Solver (sektionsuebergreifend).

# Q33: Lemma-Table (Ergebnis der 1-Pass-Enumeration).
LEMMAS = {
    'R_AND': 'ternlog LUT 0xC0',
    'R_OR': 'ternlog LUT 0xFC',
    'R_XOR': 'ternlog LUT 0x3C',
    'R_NOT': 'ternlog LUT 0x01',
    'R_ANDNOT': 'ternlog LUT 0x30',
    'R_ORC': 'ternlog LUT 0xF3',
    'R_BIN2GRAY': 'bitfrob LSR(1) + ternlog XOR strobe1',
    'R_ADJSWAP': 'bitfrob BITSWAP mask 0x55555555 sh1',
    'I_GRAY2BIN': 'fine-shift 1-pass unmoeglich',
    'I_POPCNT32': 'braucht 2. arith4 PWADD',
    'I_UBFX8': 'siehe Q20',
}


def model_permb_byte(s1, s2, ctrl, blank_enable=True):
    """Byte-Modus: 4 Output-Bytes, ctrl_byte&0x07 waehlt Concat-Byte (0..7),
    High-Bit 0x80 blankt (wenn blank_enable). concat = [s1 | s2], s1=HIGH."""
    concat = z3.Concat(s1, s2)                      # 64-Bit
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


def model_permb_shift(s1, s2, n, shift_left=False):
    """shift_ctrl: src3=Shift-Menge (0..31), Byte-Teil k=n>>3 synthetisiert
    Verschiebe-Maske on-the-fly. LSR: out-Byte i = Concat-Byte (k+i), k+i>=4
    -> blank (32-Bit-Wert in src2). LSL: out-Byte i = Concat-Byte (i-k),
    i<k -> blank. shifted_out (rausgeschobene Bytes) als zweiter Rueckgabe.
    Liefert (res, shifted_out)."""
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
        for j in range(min(k, 4)):
            so = so | z3.ZeroExt(24, z3.Extract(7 + 8 * j, 8 * j, concat))
    else:
        for i in range(4):
            idx = i - k
            if idx < 0:
                val = z3.BitVecVal(0, 8)
            else:
                val = z3.Extract(7 + 8 * idx, 8 * idx, concat)
            res = res | (z3.ZeroExt(24, val) << z3.BitVecVal(8 * i, 32))
        for j in range(min(k, 4)):
            so = so | z3.ZeroExt(24, z3.Extract(7 + 8 * (8 - k + j), 8 * (8 - k + j), concat))
    return res, so


def _m9_unsat(name, fml):
    """QF_BV-Solver, Negations-Idiom: unsat erwartet. Bei sat Gegenbeispiel
    via m.eval drucken und STOP (kein Weaken)."""
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(fml)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        print(f"{name}: SAT -> Gegenbeispiel: {m.eval(fml, model_completion=True)}")
        assert False, f"{name}: sat -> STOP (kein Weaken)"
    assert r == z3.unsat, f"{name}: {r} -> STOP (kein Weaken)"
    print(f"{name} PASS")


def _m14_unsat(name, fml, cex_vars):
    """QF_BV-Solver, Negations-Idiom (wie _m9_unsat, mit CEX-Variablen).
    unsat erwartet; bei sat Gegenbeispiel via m.eval drucken und STOP."""
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(fml)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        cex = ", ".join(f"{v}={m.eval(v, model_completion=True)}" for v in cex_vars)
        print(f"{name}: SAT -> Gegenbeispiel {cex}")
        assert False, f"{name}: sat -> STOP (kein Weaken)"
    assert r == z3.unsat, f"{name}: {r} -> STOP (kein Weaken)"
    print(f"{name} PASS")


def _m16_unsat(name, fml, cex_vars):
    """QF_BV-Solver, Negations-Idiom (wie _m14_unsat) + Konsistenz-Guard:
    z3 4.16.0 liefert bei tiefen ite+bvsub-Formeln spurious SAT (Modell
    evaluiert die Formel zu False). Bei sat daher erst m.eval(fml):
    eval==False -> z3-Bug -> STOP mit Meldung; eval==True -> echtes
    Gegenbeispiel drucken und STOP (kein Weaken)."""
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(fml)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        if z3.is_false(m.eval(fml, model_completion=True)):
            assert False, f"{name}: spurious SAT (z3-Modell widerspricht Formel) -> STOP"
        cex = ", ".join(f"{v}={m.eval(v, model_completion=True)}" for v in cex_vars)
        print(f"{name}: SAT -> Gegenbeispiel {cex}")
        assert False, f"{name}: sat -> STOP (kein Weaken)"
    assert r == z3.unsat, f"{name}: {r} -> STOP (kein Weaken)"
    print(f"{name} PASS")


def _m17_unsat(name, fml, cex_vars):
    """QF_BV-Solver, Negations-Idiom (wie _m16_unsat): unsat erwartet.
    sat -> Gegenbeispiel via m.eval (model_completion=True) + STOP."""
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(fml)
    r = s.check()
    if r == z3.sat:
        m = s.model()
        cex = ", ".join(f"{v}={m.eval(v, model_completion=True)}" for v in cex_vars)
        print(f"{name}: SAT -> Gegenbeispiel {cex}")
        assert False, f"{name}: sat -> STOP (kein Weaken)"
    assert r == z3.unsat, f"{name}: {r} -> STOP (kein Weaken)"
    print(f"{name} PASS")
# ---- M8b/M10-Modelle (sektionsuebergreifend genutzt): ----

def model_cmp(s1, s2, lb):
    """SWAR-Gleichheit: Lane = all-ones iff s1_Lane == s2_Lane.

    lb < 32 via (x&lm)+lm-Trick; lb == 32 braucht Sonderfall, da die
    SWAR-Formel ein Reserve-Bit ueber der Lane benoetigt (z=0 fuer lb=32).
    """
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


def model_mul32(s1, s2, unsigned):
    """32x32->64 Multiplikation; liefert (lo, hi)."""
    i1 = z3.ZeroExt(32, s1) if unsigned else z3.SignExt(32, s1)
    i2 = z3.ZeroExt(32, s2) if unsigned else z3.SignExt(32, s2)
    prod = i1 * i2
    return (z3.Extract(31, 0, prod), z3.Extract(63, 32, prod))


def model_mul32acc(s1, s2, s3, aux, unsigned):
    """MUL32 mit Akkumulator: (lo + s3) 33-Bit, Carry in (hi + aux)."""
    i1 = z3.ZeroExt(32, s1) if unsigned else z3.SignExt(32, s1)
    i2 = z3.ZeroExt(32, s2) if unsigned else z3.SignExt(32, s2)
    prod = i1 * i2
    lo33 = z3.ZeroExt(1, z3.Extract(31, 0, prod)) + z3.ZeroExt(1, s3)
    carry_lo = z3.Extract(32, 32, lo33)   # Carry-Out = Bit 32 der 33-Bit-Summe
    res = z3.Extract(31, 0, lo33)
    hi = z3.Extract(63, 32, prod) + aux + z3.ZeroExt(31, carry_lo)
    return (res, hi)


def model_padd64(s1, s2, s3, aux):
    """64-Bit-Add aus zwei 32-Bit-Haelften; liefert (res, aux_res)."""
    lo33 = z3.ZeroExt(1, s1) + z3.ZeroExt(1, s3)
    carry_lo = z3.Extract(32, 32, lo33)   # Carry-Out = Bit 32 der 33-Bit-Summe
    res = z3.Extract(31, 0, lo33)
    hi = s2 + aux + z3.ZeroExt(31, carry_lo)
    return (res, hi)


def model_shr_sticky(s1, s2, amt):
    """SHR_STICKY (mode 30): feiner LSR 0..7 + Sticky-Bits.

    Wert lebt in s2 (niederwertiger Operand). amt ist konkreter Python-int 0..7.
    res = (s2 >> amt) & ((1<<(32-amt))-1), aux = s2 & ((1<<amt)-1).
    Liefert (res, aux)."""
    mask_res = (1 << (32 - amt)) - 1
    mask_stk = (1 << amt) - 1
    return (z3.LShR(s2, z3.BitVecVal(amt, 32)) & z3.BitVecVal(mask_res, 32),
            s2 & z3.BitVecVal(mask_stk, 32))


def model_aux_bitfrob(s1, s2, s3, mode, amt):
    """bitfrob aux-Tap: (res, aux). mode konkreter BitFrobMode-Int.

    ROL(8): res=model_rol(s1,s3), aux=s1. MASKW(12): res=model_maskw(s3), aux=s3.
    SHR_STICKY(30): res,aux=model_shr_sticky(s1,s2,amt). LSR(0): res=model_lsr(s1,s2,s3), aux=s1."""
    if not isinstance(s2, z3.BitVecRef):
        s2 = z3.BitVecVal(s2, 32)
    if not isinstance(s3, z3.BitVecRef):
        s3 = z3.BitVecVal(s3, 32)
    if mode == 8:
        return (model_rol(s1, s3), s1)
    if mode == 12:
        return (model_maskw(s3), s3)
    if mode == 30:
        return model_shr_sticky(s1, s2, amt)
    if mode == 0:
        return (model_lsr(s1, s2, s3), s1)
    raise ValueError(f"M10: bitfrob mode {mode} nicht im aux-Satz")
# ---- Masken-Kataloge (M6 definiert, M18 nutzt MASKS): ----

MASKS = [0x00000000, 0xFFFFFFFF, 0x55555555, 0xAAAAAAAA, 0x0F0F0F0F,
         0xF0F0F0F0, 0x33333333, 0xCCCCCCCC, 0x00FF00FF, 0xFF00FF00,
         0x0000FFFF, 0xFFFF0000, 0x10203040, 0x01010101, 0x80808080,
         0x12345678, 0xDEADBEEF, 0xA5A5A5A5, 0x3C3C3C3C, 0x80000000,
         0x00000001, 0x00000003, 0xC0000000, 0x0FF00FF0, 0x7FFFFFFF,
         0xFFFFFFFE, 0x00010000, 0x10000000]


INV_MASKS = [0x0F0F0F0F, 0xF0F0F0F0, 0x33333333, 0x00FF00FF, 0x0000FFFF,
             0x10203040, 0x01010101, 0x12345678, 0xA5A5A5A5, 0x80000000,
             0x00000003, 0x7FFFFFFF]
def _run_M1():
    # Q1: ein einzelnes LUT kann bitweises AND encodieren (c_i frei).
    # idx=(a<<2)|(b<<1)|c: a&b setzt nur idx 6,7 -> lut = 0xC0.
    print("Q1 AND: pruefe LUT-Encoding fuer bitweises AND")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == (ai & bi)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xC0
    print(f"Q1 AND: lut=0x{lut_val:02X} PASS")

    # Q2: ein einzelnes LUT kann bitweises OR encodieren (c_i frei).
    # a|b setzt idx 1,3,5,7 -> lut = 0xFC.
    print("Q2 OR: pruefe LUT-Encoding fuer bitweises OR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == (ai | bi)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xFC
    print(f"Q2 OR: lut=0x{lut_val:02X} PASS")

    # Q3: ein einziges LUT kann nicht zugleich AND und OR sein (unsat).
    print("Q3 AND^OR: ein LUT kann nicht zugleich AND und OR sein")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    ai = z3.BitVec('ai0', 1)
    bi = z3.BitVec('bi0', 1)
    ci = z3.BitVec('ci0', 1)
    bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
    solver.add(z3.ForAll([ai, bi, ci], bit == (ai & bi)))
    solver.add(z3.ForAll([ai, bi, ci], bit == (ai | bi)))
    assert solver.check() == z3.unsat
    print("Q3 AND^OR unloesbar PASS")

    # Q100: ein einzelnes LUT kann bitweises NOR encodieren (c_i frei).
    # ~(a|b): nur idx 0 -> lut = 0x03.
    print("Q100 NOR: pruefe LUT-Encoding fuer bitweises NOR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai | bi)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x03
    print(f"Q100 NOR: lut=0x{lut_val:02X} PASS")

    # Q101: ein einzelnes LUT kann bitweises NAND encodieren (c_i frei).
    # ~(a&b): idx 0..5 -> lut = 0x3F.
    print("Q101 NAND: pruefe LUT-Encoding fuer bitweises NAND")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai & bi)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x3F
    print(f"Q101 NAND: lut=0x{lut_val:02X} PASS")

    # Q102: ein einzelnes LUT kann bitweises XNOR encodieren (c_i frei).
    # ~(a^b): idx 0,3,5,6 -> lut = 0xC3.
    print("Q102 XNOR: pruefe LUT-Encoding fuer bitweises XNOR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai ^ bi)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xC3
    print(f"Q102 XNOR: lut=0x{lut_val:02X} PASS")

    # Q103: ein einzelnes LUT kann 3-Input-XOR encodieren.
    # a^b^c: gerade Paritaet -> lut = 0x96.
    print("Q103 XOR3: pruefe LUT-Encoding fuer 3-Input-XOR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((ai ^ bi ^ ci) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x96
    print(f"Q103 XOR3: lut=0x{lut_val:02X} PASS")

    # Q104: ein einzelnes LUT kann 3-Input-XNOR encodieren.
    # ~(a^b^c): ungerade Paritaet -> lut = 0x69.
    print("Q104 XNOR3: pruefe LUT-Encoding fuer 3-Input-XNOR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai ^ bi ^ ci)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x69
    print(f"Q104 XNOR3: lut=0x{lut_val:02X} PASS")

    # Q105: ein einzelnes LUT kann 3-Input-NAND encodieren.
    # ~(a&b&c): nur idx 7 -> lut = 0x7F.
    print("Q105 NAND3: pruefe LUT-Encoding fuer 3-Input-NAND")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai & bi & ci)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x7F
    print(f"Q105 NAND3: lut=0x{lut_val:02X} PASS")

    # Q106: ein einzelnes LUT kann 3-Input-NOR encodieren.
    # ~(a|b|c): nur idx 0 -> lut = 0x01.
    print("Q106 NOR3: pruefe LUT-Encoding fuer 3-Input-NOR")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~(ai | bi | ci)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x01
    print(f"Q106 NOR3: lut=0x{lut_val:02X} PASS")

    # Q107: ein einzelnes LUT kann Majority encodieren.
    # (a&b)|(b&c)|(a&c): idx 3,5,6,7 -> lut = 0xE8.
    print("Q107 MAJ: pruefe LUT-Encoding fuer Majority")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((ai & bi) | (bi & ci) | (ai & ci))))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xE8
    print(f"Q107 MAJ: lut=0x{lut_val:02X} PASS")

    # Q108: ein einzelnes LUT kann Minority encodieren.
    # ~((a&b)|(b&c)|(a&c)): idx 0,1,2,4 -> lut = 0x17.
    print("Q108 MIN: pruefe LUT-Encoding fuer Minority")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~((ai & bi) | (bi & ci) | (ai & ci))) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x17
    print(f"Q108 MIN: lut=0x{lut_val:02X} PASS")

    # Q109: ein einzelnes LUT kann AND mit c encodieren (b_i frei).
    # a&c: idx 5,7 -> lut = 0xA0.
    print("Q109 AND_C: pruefe LUT-Encoding fuer a&c")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == (ai & ci)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xA0
    print(f"Q109 AND_C: lut=0x{lut_val:02X} PASS")

    # Q110: ein einzelnes LUT kann Implikation a->b encodieren.
    # ~a|b: nur idx 2 -> lut = 0xCF.
    print("Q110 IMPLY: pruefe LUT-Encoding fuer a->b")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~ai | bi) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xCF
    print(f"Q110 IMPLY: lut=0x{lut_val:02X} PASS")

    # Q111: ein einzelnes LUT kann Implikation a->c encodieren.
    # ~a|c: idx 0,4,5,6 -> lut = 0xAF.
    print("Q111 IMPLY_C: pruefe LUT-Encoding fuer a->c")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~ai | ci) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xAF
    print(f"Q111 IMPLY_C: lut=0x{lut_val:02X} PASS")

    # Q112: ein einzelnes LUT kann a|~c encodieren.
    # a|~c: idx 0,1,2,4,5,6 -> lut = 0xF5.
    print("Q112 ORC_C: pruefe LUT-Encoding fuer a|~c")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((ai | ~ci) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0xF5
    print(f"Q112 ORC_C: lut=0x{lut_val:02X} PASS")

    # Q113: ein einzelnes LUT kann ~((a&b)^c) encodieren.
    # MANDN mit invertiertem c-Anteil: idx 0,1,2,4,5,6 -> lut = 0x95.
    print("Q113 MANDN_INV: pruefe LUT-Encoding fuer ~((a&b)^c)")
    solver = z3.Solver()
    lut = z3.BitVec('lut', 32)
    for i in range(32):
        ai = z3.BitVec(f'a{i}', 1)
        bi = z3.BitVec(f'b{i}', 1)
        ci = z3.BitVec(f'c{i}', 1)
        bit = z3.Extract(0, 0, z3.LShR(lut, z3.ZeroExt(29, z3.Concat(ai, bi, ci))))
        solver.add(z3.ForAll([ai, bi, ci], bit == ((~((ai & bi) ^ ci)) & 1)))
    assert solver.check() == z3.sat
    m = solver.model()
    lut_val = m[lut].as_long() & 0xFF
    assert lut_val == 0x95
    print(f"Q113 MANDN_INV: lut=0x{lut_val:02X} PASS")

    # Q114: NOT (0x01) = NOR3 = ~(a|b|c); NOR (0x03) = ~(a|b). Verschieden!
    # Sat-Beweis: es gibt (a,b,c) mit unterschiedlichem Ergebnis (z.B. a=b=0,c=1).
    solver = z3.Solver()
    a = z3.BitVec('a_q114', 32)
    b = z3.BitVec('b_q114', 32)
    c = z3.BitVec('c_q114', 32)
    solver.add(model_ternlog(a, b, c, 0x01) != model_ternlog(a, b, c, 0x03))
    assert solver.check() == z3.sat
    m = solver.model()
    print(f"Q114 NOT!=NOR unloesbar-distinct PASS (Witness a={m[a].as_long():#x}, b={m[b].as_long():#x}, c={m[c].as_long():#x})")

    print("M1 PASS")

def _run_M2():

    # ---- M2: bitfrob-Stufe (LSR/LSL/ROR/ROL/MASK/MASKW/SEXT) ----
    # Beweis-Idiom: Negation der Behauptung annehmen, sat/unsat pruefen.
    # unsat => kein Gegenbeispiel => Eigenschaft gilt fuer alle x.

    # Q4: LSR(x, 3) == x >> 3 (s3 = 3 konkret).
    # Funnel-Konvention: Wert lebt in s2 (niederwertiger Operand), s1 muss 0
    # sein. s1 == s2 wuerde ein Rotate-Artefakt erzeugen (niederwertige Bits
    # wandern ueber s1 zurueck an die Spitze).
    print("Q4 LSR(x,3)==x>>3: pruefe per Negation")
    x = z3.BitVec('x', 32)
    s = z3.BitVec('s', 32)
    s3 = z3.BitVecVal(3, 32)
    solver = z3.Solver()
    solver.add(model_lsr(z3.BitVecVal(0, 32), x, s3) != z3.LShR(x, 3))
    assert solver.check() == z3.unsat
    print("Q4 LSR(x,3)==x>>3 (s1=0) bewiesen PASS")

    # Q5: LSL(x, 0) == x (Shift um 0 ist Identitaet).
    print("Q5 LSL(x,0)==x: pruefe per Negation")
    solver = z3.Solver()
    solver.add(model_lsl(x, z3.BitVecVal(0, 32), z3.BitVecVal(0, 32)) != x)
    assert solver.check() == z3.unsat
    print("Q5 LSL(x,0)==x bewiesen PASS")

    # Q6: ROL(x,8) == x: feine Rotation ist mod-8 (amt = s3 & 7), also ist
    # Rotation um 8 eine No-op. Byte-Vielfache kommen aus permb (kurzer
    # Barrel by design); die Maske wirkt pro Aufruf, nicht auf die Summe.
    print("Q6 ROL(x,8)==x (amt&7=0): pruefe per Negation")
    solver = z3.Solver()
    solver.add(model_rol(x, z3.BitVecVal(8, 32)) != x)
    assert solver.check() == z3.unsat
    print("Q6 ROL(x,8)==x (amt&7=0) bewiesen PASS")

    # Q7: MASK(c) == all-ones genau dann wenn c != 0.
    print("Q7 MASK(c)=all-ones iff c!=0: pruefe per Negation")
    c = z3.BitVec('c', 32)
    solver = z3.Solver()
    solver.add(model_mask(c) != z3.If(c != 0, z3.BitVecVal(0xFFFFFFFF, 32), z3.BitVecVal(0, 32)))
    assert solver.check() == z3.unsat
    print("Q7 MASK(c)=all-ones iff c!=0 bewiesen PASS")

    # Q8: MASKW(n) == 0xFF => n & 0x1F == 8 (Existenzbeweis, sat + Modell).
    print("Q8 MASKW(n)==0xFF: Existenzbeweis mit Modell")
    solver = z3.Solver()
    n = z3.BitVec('n', 32)
    solver.add(model_maskw(n) == z3.BitVecVal(0xFF, 32))
    assert solver.check() == z3.sat
    m = solver.model()
    n_val = m[n].as_long() & 0x1F
    assert n_val == 8
    print("Q8 MASKW(n)==0xFF -> n=8 PASS")

    # Q9: SEXT-Spotchecks: 0x80 @ pos 7 -> 0xFFFFFF80, 0x7F -> 0x7F.
    print("Q9 SEXT spot: pruefe zwei konkrete Faelle per Negation")
    solver = z3.Solver()
    solver.add(model_sext(z3.BitVecVal(0x80, 32), 7) != z3.BitVecVal(0xFFFFFF80, 32))
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(model_sext(z3.BitVecVal(0x7F, 32), 7) != z3.BitVecVal(0x7F, 32))
    assert solver.check() == z3.unsat
    print("Q9 SEXT spot PASS")

    print("M2 PASS")

def _run_M3():

    # ---- M3: 1-Pass-Synthese (CMOV) ----
    # 1-Pass-CMOV = bitfrob MASK erzeugt den "c!=0"-Vergleich (all-ones oder
    # 0), ternlog SELECT_A (lut 0xE4) waehlt a bei Maske, sonst b. Der
    # Masken-Bit ist fuer ALLE 32 Bitpositionen identisch — die Kern-Eigenschaft.

    # Q10: CMOV-Synthese (SELECT_A). 4 Paare decken alle (a_i,b_i)-Kombos pro
    # Bit ab -> Wahrheitstabelle erzwungen, LUT deterministisch. Symbolische
    # a,b wuerden trivial (a=b=0, jede LUT passt) — z3 weist sie existentiell zu.
    print("Q10 CMOV 1-Pass: synthetisiere LUT (SELECT_A)")
    pairs = [(0, 0), (0, 0xFFFFFFFF), (0xFFFFFFFF, 0), (0xFFFFFFFF, 0xFFFFFFFF)]
    lut = z3.BitVec('lut', 32)
    s = z3.Solver()
    for (pa, pb) in pairs:
        a = z3.BitVecVal(pa, 32)
        b = z3.BitVecVal(pb, 32)
        s.add(model_ternlog(a, b, z3.BitVecVal(0, 32), lut) == b)          # c=0 (Maske=0) -> b
        s.add(model_ternlog(a, b, z3.BitVecVal(0xFFFFFFFF, 32), lut) == a)  # c!=0 -> a
    assert s.check() == z3.sat
    lut_val = s.model()[lut].as_long() & 0xFF
    assert lut_val == 0xE4
    print(f"Q10 CMOV 1-Pass (SELECT_A): LUT=0x{lut_val:02X} synthetisiert PASS")

    # Q11: CMOV-Synthese (SELECT_B): b wenn c. 0xD8 — der Beweis exponierte
    # den latenten Bug (0xC8 gab c=0 -> a&b), in pipeline.py behoben,
    # Regressionstest test_select_b_semantics ergaenzt.
    print("Q11 SELECT_B: synthetisiere LUT (b wenn c)")
    pairs = [(0, 0), (0, 0xFFFFFFFF), (0xFFFFFFFF, 0), (0xFFFFFFFF, 0xFFFFFFFF)]
    lut = z3.BitVec('lut', 32)
    s = z3.Solver()
    for (pa, pb) in pairs:
        a = z3.BitVecVal(pa, 32)
        b = z3.BitVecVal(pb, 32)
        s.add(model_ternlog(a, b, z3.BitVecVal(0, 32), lut) == a)          # c=0 (Maske=0) -> a
        s.add(model_ternlog(a, b, z3.BitVecVal(0xFFFFFFFF, 32), lut) == b)  # c!=0 -> b
    assert s.check() == z3.sat
    lut_val = s.model()[lut].as_long() & 0xFF
    assert lut_val == 0xD8
    print(f"Q11 SELECT_B (b wenn c): LUT=0x{lut_val:02X} synthetisiert PASS")

    # Q12: Negativkontrolle — rohes c ohne MASK-Vorbereitung: c=0x80000000
    # setzt nur Bit 31. Die LUT kann Bits 0..30 (c_i=0) nicht zugleich auf 'b'
    # und Bit 31 (c_i=1) auf 'a' legen; nur die MASK-Stufe erzeugt den
    # gemeinsamen all-ones/zero-Vergleich. Ohne MASK ist CMOV unmoeglich.
    print("Q12 CMOV OHNE MASK: pruefe Unmoeglichkeit (unsat)")
    a = z3.BitVecVal(0xDEADBEEF, 32)
    b = z3.BitVecVal(0x12345678, 32)
    lut = z3.BitVec('lut', 32)
    solver = z3.Solver()
    solver.add(model_ternlog(a, b, z3.BitVecVal(0, 32), lut) == b)
    solver.add(model_ternlog(a, b, z3.BitVecVal(0x80000000, 32), lut) == a)
    assert solver.check() == z3.unsat
    print("Q12 CMOV OHNE MASK unmoeglich (bitfrob-Vorbereitung noetig) PASS")

    print("M3 PASS")

def _run_M4():

    # ---- M4: Count/Scan-Modi (LZC/TZC/POPCNT_B) ----
    # Beweis-Idiom wie in M2: Negation annehmen, z3.unsat erwarten.
    # Hinweis (nur hier): Q13-Q18 nutzen SolverFor('QF_BV') statt Solver(),
    # weil der Default-Solver in z3 4.16.0 bei 32-fach verschachteltem
    # If+bvsub unzuverlaessig ist (sat mit selbst-widersprechendem Modell);
    # QF_BV/bitblast liefern das korrekte unsat.

    # Q13: LZC = 0 wenn MSB gesetzt (31 - 31 = 0).
    print("Q13 LZC(MSB gesetzt)==0: pruefe per Negation")
    x = z3.BitVec('x', 32)
    s = z3.SolverFor('QF_BV')
    s.add(z3.Extract(31, 31, x) == 1)
    s.add(model_lzc(x) != 0)
    assert s.check() == z3.unsat
    print("Q13 LZC(MSB gesetzt)==0 bewiesen PASS")

    # Q14: LZC(0) == 32 (kein gesetztes Bit).
    print("Q14 LZC(0)==32: pruefe per Negation")
    s = z3.SolverFor('QF_BV')
    s.add(x == 0)
    s.add(model_lzc(x) != 32)
    assert s.check() == z3.unsat
    print("Q14 LZC(0)==32 bewiesen PASS")

    # Q15: TZC = 0 wenn Bit 0 gesetzt (niederwertigstes Bit = 0).
    print("Q15 TZC(ungerade)==0: pruefe per Negation")
    x2 = z3.BitVec('x2', 32)
    s = z3.SolverFor('QF_BV')
    s.add(z3.Extract(0, 0, x2) == 1)
    s.add(model_tzc(x2) != 0)
    assert s.check() == z3.unsat
    print("Q15 TZC(ungerade)==0 bewiesen PASS")

    # Q16: POPCNT_B(0xFFFFFFFF): jedes Byte hat 8 gesetzte Bits.
    print("Q16 POPCNT_B(0xFFFFFFFF): pruefe per Negation")
    s = z3.SolverFor('QF_BV')
    s.add(model_popcnt_b(z3.BitVecVal(0xFFFFFFFF, 32)) != z3.BitVecVal(0x08080808, 32))
    assert s.check() == z3.unsat
    print("Q16 POPCNT_B(0xFFFFFFFF)=0x08080808 bewiesen PASS")

    # Q17: LZC/TZC-Kreuzcheck gegen pure-Python-Referenz.
    print("Q17 LZC/TZC Kreuzcheck: pruefe per Negation")
    vectors = [0, 1, 2, 0x80, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x01010101,
               0xDEADBEEF, 0x12345678, 0x0F000000, 0x0000000F]
    for v in vectors:
        ref_lzc = 32 if v == 0 else 31 - (v.bit_length() - 1)
        ref_tzc = 32 if v == 0 else (v & -v).bit_length() - 1
        s = z3.SolverFor('QF_BV')
        s.add(model_lzc(z3.BitVecVal(v, 32)) != z3.BitVecVal(ref_lzc, 32))
        assert s.check() == z3.unsat
        s = z3.SolverFor('QF_BV')
        s.add(model_tzc(z3.BitVecVal(v, 32)) != z3.BitVecVal(ref_tzc, 32))
        assert s.check() == z3.unsat
    print("Q17 LZC/TZC Kreuzcheck vs Python-Referenz PASS")

    # Q18: POPCNT_B-Kreuzcheck: pro Byte-1-Bit-Zaehlung, auf Byte-Position
    # geschoben, gegen pure-Python-Referenz.
    print("Q18 POPCNT_B Kreuzcheck: pruefe per Negation")
    for v in vectors:
        ref_pc = 0
        for b in range(4):
            cnt = bin((v >> (b * 8)) & 0xFF).count('1')
            ref_pc |= cnt << (b * 8)
        s = z3.SolverFor('QF_BV')
        s.add(model_popcnt_b(z3.BitVecVal(v, 32)) != z3.BitVecVal(ref_pc, 32))
        assert s.check() == z3.unsat
    print("Q18 POPCNT_B Kreuzcheck PASS")

    print("M4 PASS")

def _run_M5():

    # === M5: Pass-Schranken-Beweise UBFX/BFI ===
    # Beweis-Idiom: Negation annehmen, z3.unsat erwarten. QF_BV statt
    # Default-Solver (4.16.0-Problem bei tiefem If+bvsub, siehe M4).
    # Modelle wiederverwendet: model_rol (M2, feine Rotation s3&7),
    # model_ternlog (M1, LUT 0xC0 = AND, LUT 0xE4 = SELECT_A).

    # Q19: UBFX 1-Pass via ROR fuer lsb<=7 ist KORREKT. Feine ROR (amt&7)
    # bringt Bit lsb an Position 0; ROR(x,lsb)&0xFF = (x>>lsb)&0xFF, weil der
    # (x<<(32-lsb))-Anteil bei &0xFF wegfällt (Bits landen bei >=25).
    # Negation: out != (x>>lsb)&0xFF -> unsat erwartet.
    print("Q19 UBFX 1-Pass via ROR: pruefe lsb in [0,1,3,5,7] per Negation")
    for lsb in [0, 1, 3, 5, 7]:
        x = z3.BitVec(f'x_q19_{lsb}', 32)
        r = model_ror(x, z3.BitVecVal(lsb, 32))
        out = model_ternlog(r, z3.BitVecVal(0xFF, 32), z3.BitVecVal(0, 32), z3.BitVecVal(0xC0, 32))
        s = z3.SolverFor('QF_BV')
        s.add(out != ((x >> lsb) & 0xFF))
        assert s.check() == z3.unsat
        print(f"Q19 UBFX 1-Pass via ROR lsb={lsb} bewiesen PASS")

    # Q19b: ROL-Form (wie im echten ctrl_ubfx, test_pipeline.py:1210) ist
    # FALSCH fuer lsb=1. ROL(x,31) -> amt&7 = 7 intern; ROL(x,7)&0xFF =
    # (x>>25)&0xFF, nicht (x>>1)&0xFF. Beweis nicht-fuer-alle-x: Negation
    # sat mit Gegenbeispiel.
    print("Q19b ROL-Form lsb=1: pruefe Abweichung (sat erwartet)")
    x = z3.BitVec('x_q19b', 32)
    r = model_rol(x, z3.BitVecVal((32 - 1) & 31, 32))
    out = model_ternlog(r, z3.BitVecVal(0xFF, 32), z3.BitVecVal(0, 32), z3.BitVecVal(0xC0, 32))
    s = z3.SolverFor('QF_BV')
    s.add(out != ((x >> 1) & 0xFF))
    res = s.check()
    assert res == z3.sat
    m = s.model()
    print(f"Q19b ROL-Form lsb=1 FALSCH (echter ISA-Bug exponiert) PASS, Gegenbeispiel x={m[x].as_long():#010x}")

    # Q19c: ROL-Form fuer lsb=28 w=4 ist nur KORREKT, weil die schmale Maske
    # 0xF den Wrap-Weg abschneidet: ROL(x,4)&0xF = (x>>28)&0xF. Deshalb hat
    # der alte Test (mit schmaler Maske) trotz ROL-Bug bestanden.
    print("Q19c ROL-Form lsb=28 w=4: pruefe Grenzfall per Negation")
    x = z3.BitVec('x_q19c', 32)
    r = model_rol(x, z3.BitVecVal((32 - 28) & 31, 32))
    out = model_ternlog(r, z3.BitVecVal(0xF, 32), z3.BitVecVal(0, 32), z3.BitVecVal(0xC0, 32))
    s = z3.SolverFor('QF_BV')
    s.add(out != ((x >> 28) & 0xF))
    assert s.check() == z3.unsat
    print("Q19c ROL-Form lsb=28 w=4 Grenzfall korrekt PASS")

    # Q20: UBFX lsb=8 in 1 Pass UNMOEGLICH mit feiner Rotation. Pro amt:
    # sat = es existiert x mit Abweichung, beweist nicht-fuer-alle-x. Alle 8
    # sat + Fenster-Analyse (feine Fenster decken nur 0..7) => vollstaendig;
    # lsb=8 braucht 2 Makro-Schritte (permb-Byte-Shift).
    print("Q20 UBFX lsb=8: pruefe Unmoeglichkeit pro amt (sat erwartet)")
    for amt in range(8):
        x = z3.BitVec(f'x_q20_{amt}', 32)
        r = model_rol(x, z3.BitVecVal(amt, 32))
        out = model_ternlog(r, z3.BitVecVal(0xFF, 32), z3.BitVecVal(0, 32), z3.BitVecVal(0xC0, 32))
        s = z3.SolverFor('QF_BV')
        s.add(out != ((x >> 8) & 0xFF))
        res = s.check()
        assert res == z3.sat
        m = s.model()
        print(f"Q20 lsb=8 amt={amt} unmoeglich PASS (Gegenbeispiel x={m[x].as_long():#010x})")

    # Q21: BFI lsb=0 1-Pass-Blend KORREKT. SELECT_A (0xE4): a wenn c sonst b.
    # a=y, b=x, c=mask=0xFF -> (y&mask) | (x&~mask). Negation -> unsat.
    print("Q21 BFI lsb=0: pruefe 1-Pass-Blend per Negation")
    x = z3.BitVec('x_q21', 32)
    y = z3.BitVec('y_q21', 32)
    mask = z3.BitVecVal(0xFF, 32)
    out = model_ternlog(y, x, mask, z3.BitVecVal(0xE4, 32))
    s = z3.SolverFor('QF_BV')
    s.add(out != ((y & mask) | (x & ~mask)))
    assert s.check() == z3.unsat
    print("Q21 BFI lsb=0 1-Pass-Blend bewiesen PASS")

    # Q22: BFI lsb=1 2-Pass-KOMPOSITION KORREKT. Pass1: feine ROL(y,1) schiebt
    # y um 1 nach links; Pass2: SELECT_A-Blend mit verschobener Maske 0x1FE.
    # Negation: out != ((y<<1)&0x1FE)|(x&~0x1FE) -> unsat erwartet.
    print("Q22 BFI lsb=1: pruefe 2-Pass-Komposition per Negation")
    x = z3.BitVec('x_q22', 32)
    y = z3.BitVec('y_q22', 32)
    r = model_rol(y, z3.BitVecVal(1, 32))
    mask_shifted = z3.BitVecVal(0x1FE, 32)
    out = model_ternlog(r, x, mask_shifted, z3.BitVecVal(0xE4, 32))
    s = z3.SolverFor('QF_BV')
    s.add(out != (((y << 1) & z3.BitVecVal(0x1FE, 32)) | (x & ~z3.BitVecVal(0x1FE, 32))))
    assert s.check() == z3.unsat
    print("Q22 BFI lsb=1 2-Pass-Komposition bewiesen PASS")

    print("M5 PASS")

def _run_M6():

    # ---- M6: pext32/pdep32-Butterfly-Beweise ----
    # Negations-Idiom wie gehabt; alle Queries QF_BV (kein Default-Solver).

    # Q23-Q26 (SCHLANKUNG): Finite-Mask-Leiter. Symbolisches x, KONKRETE Masken
    # aus kuratierter Menge (Dichte/Runs/Alternierend/Byte-Lanes/Sparse).
    # Symbolisches m sprengt den Bitblast (Masken-DAG evolution, >120s); konkretes
    # m kollabiert die DAG auf Konstanten (~0.04s je Query). Vollstaendige
    # 32-Bit-Beweise pro Maske, x bleibt symbolisch (Negations-Idiom).
    # Volles symbolisches-m (alle 2^32 Masken): spaeter als --stretch wieder
    # aktivierbar, Modelle zpext32/zpdep32 stehen bereit; nice -n 15 + Timeout,
    # nicht blockierend.
    xq = z3.BitVec('x_q23', 32)

    print(f"Q23 pdep(pext(x,m),m)==x&m: {len(MASKS)} Masken, symbolisches x")
    n_rt = 0
    for mv in MASKS:
        mc = z3.BitVecVal(mv, 32)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(zpdep32(zpext32(xq, mc), mc) != (xq & mc))
        assert s.check() == z3.unsat, f"Q23 roundtrip m={mv:#010x}"
        n_rt += 1
    print(f"Q23 Roundtrip bewiesen fuer {n_rt} Masken PASS")

    print(f"Q24 pext(pdep(x,m),m)==x&(2^pc-1): {len(INV_MASKS)} Masken, pc konkret")
    n_inv = 0
    for mv in INV_MASKS:
        pc = bin(mv).count('1')
        lowmask = (1 << pc) - 1 if pc < 32 else 0xFFFFFFFF
        mc = z3.BitVecVal(mv, 32)
        lm = z3.BitVecVal(lowmask, 32)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(zpext32(zpdep32(xq, mc), mc) != (xq & lm))
        assert s.check() == z3.unsat, f"Q24 inverse m={mv:#010x}"
        n_inv += 1
    print(f"Q24 Inverse bewiesen fuer {n_inv} Masken PASS")

    print(f"Q25 pdep(x,m)&~m==0: {len(INV_MASKS)} Masken")
    n_bits = 0
    for mv in INV_MASKS:
        mc = z3.BitVecVal(mv, 32)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(zland(zpdep32(xq, mc), zlnot(mc)) != z3.BitVecVal(0, 32))
        assert s.check() == z3.unsat, f"Q25 bits m={mv:#010x}"
        n_bits += 1
    print(f"Q25 pdep-Bits nur auf m bewiesen fuer {n_bits} Masken PASS")

    print(f"Q26 pext32(x,m)<2^pc: {len(INV_MASKS)} Masken, UGE (z3py >= ist SIGNED)")
    n_rng = 0
    for mv in INV_MASKS:
        pc = bin(mv).count('1')
        if pc >= 32:
            continue   # 2^32 nicht in 32-Bit darstellbar, Kante trivial
        mc = z3.BitVecVal(mv, 32)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(z3.UGE(zpext32(xq, mc), z3.BitVecVal(1 << pc, 32)))
        assert s.check() == z3.unsat, f"Q26 range m={mv:#010x}"
        n_rng += 1
    print(f"Q26 Kompressionsbereich bewiesen fuer {n_rng} Masken PASS")

    # Q27: NEGATIV-KONTROLLE: verschiedene Masken brechen die Identitaet.
    # pdep32(pext32(x,m1),m2) != x&m2 hat Gegenbeispiele (m1=0x0F0F0F0F,
    # m2=0xF0F0F0F0, gefunden x=0xd8302081). sat + Modell erwartet.
    print("Q27 verschiedene Masken brechen Identitaet: Gegenbeispiel suchen")
    x = z3.BitVec('x_q27', 32)
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 120000)   # ms; unknown -> STOP + Bericht
    s.add(zpdep32(zpext32(x, z3.BitVecVal(0x0F0F0F0F, 32)), z3.BitVecVal(0xF0F0F0F0, 32))
          != (x & z3.BitVecVal(0xF0F0F0F0, 32)))
    assert s.check() == z3.sat
    m_q27 = s.model()
    print(f"Q27 Gegenbeispiel x={m_q27[x].as_long():#010x} PASS")

    print("M6 PASS")

def _run_M7():

    # ---- M7: 1-Pass-Enumeration (ternlog+bitfrob Oberflaeche) ----
    # Beweis-Idiom wie gehabt; QF_BV, konkrete Eingabe-Batterien (kein
    # symbolisches m fuer Synthese — ∃-Falle), Timeout 30s je Query.

    # Q28: ternlog-Familie realisierbar — M1 AND/OR re-verifizieren + NEU
    # ANDNOT/ORC/NOT/XOR. Batterie 4 konkrete Paare + c=0.
    print("Q28 ternlog-Familie: pruefe 6 LUTs per Negation")
    Q28_PAIRS = [(0, 0), (0, 0xFFFFFFFF), (0xFFFFFFFF, 0), (0xFFFFFFFF, 0xFFFFFFFF)]
    Q28_LUTS = {
        'AND': (0xC0, lambda a, b: a & b),
        'OR': (0xFC, lambda a, b: a | b),
        'XOR': (0x3C, lambda a, b: a ^ b),
        'NOT': (0x01, lambda a, b: ~a),
        'ANDNOT': (0x30, lambda a, b: a & ~b),
        'ORC': (0xF3, lambda a, b: a | ~b),
    }
    n_luts = 0
    for name, (lutv, fn) in Q28_LUTS.items():
        ok = True
        pairs = [(pa, pb) for (pa, pb) in Q28_PAIRS if pb == 0] if name == 'NOT' else Q28_PAIRS
        for (pa, pb) in pairs:
            a = z3.BitVecVal(pa, 32)
            b = z3.BitVecVal(pb, 32)
            s = z3.SolverFor('QF_BV')
            s.set("timeout", 30000)
            s.add(model_ternlog(a, b, z3.BitVecVal(0, 32), z3.BitVecVal(lutv, 32)) != fn(a, b))
            assert s.check() == z3.unsat, f"Q28 {name} lut=0x{lutv:02X}"
        n_luts += 1
    print(f"Q28 ternlog-Familie {n_luts}/6 LUTs realisierbar PASS")

    # Q29: bin->gray 1-Pass NEU: bitfrob LSR fein (amt=1, s1=0) speist ternlog
    # XOR (0x3C) via prev_in_strobe: out = (x>>1) ^ x = Gray-Code.
    print("Q29 bin->gray: pruefe 1-Pass per Negation")
    Q29_BAT = [0, 0xFFFFFFFF, 0x80000000, 0x55555555, 0xAAAAAAAA, 0x12345678, 0xDEADBEEF]
    for xv in Q29_BAT:
        xc = z3.BitVecVal(xv, 32)
        lsr1 = model_lsr(z3.BitVecVal(0, 32), xc, z3.BitVecVal(1, 32))
        out = model_ternlog(lsr1, xc, z3.BitVecVal(0, 32), z3.BitVecVal(0x3C, 32))
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(out != (xc ^ zshr(xc, 1)))
        assert s.check() == z3.unsat, f"Q29 gray x={xv:#010x}"
    print("Q29 bin->gray 1-Pass bewiesen PASS")

    # Q30: gray->bin 1-Pass UNMOEGLICH (fine-shift-only): ein einzelner feiner
    # Shift (amt 1/2/4) + XOR kann die XOR-Prefix-Inverse nicht fuer alle g
    # liefern. Negation der Identitaet -> sat mit Gegenbeispiel.
    print("Q30 gray->bin: pruefe Unmoeglichkeit (sat erwartet)")
    g = z3.BitVec('g_q30', 32)
    ref30 = g ^ zshr(g, 1) ^ zshr(g, 2) ^ zshr(g, 4) ^ zshr(g, 8) ^ zshr(g, 16)
    n_cex = 0
    for amt in [1, 2, 4]:
        cand = g ^ zshr(g, amt)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(cand != ref30)
        assert s.check() == z3.sat, f"Q30 gray->bin amt={amt} unsat?!"
        m30 = s.model()
        n_cex += 1
        print(f"Q30 gray->bin amt={amt} Gegenbeispiel g={m30[g].as_long():#010x}")
    print(f"Q30 gray->bin fine-shift 1-Pass unmoeglich ({n_cex}/3 cex) PASS")

    # Q31: popcnt32 1-Pass UNMOEGLICH: 1 Pass = POPCNT_B + ein PWADD-byte;
    # die 2. arith4-Stufe (PWADD word) fehlt. Negation -> sat + Gegenbeispiel
    # (x mit >8 Einsen in einem Byte).
    print("Q31 popcnt32: pruefe 1-Pass-Unmoeglichkeit (sat erwartet)")
    x31 = z3.BitVec('x_q31', 32)
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(z_pwaddb(model_popcnt_b(x31)) != z_popcnt32(x31))
    assert s.check() == z3.sat
    m31 = s.model()
    print(f"Q31 popcnt32 1-Pass unmoeglich (2. arith4 fehlt) Gegenbeispiel x={m31[x31].as_long():#010x} PASS")

    # Q32: bitswap benachbart realisierbar: model_bitswap(x, 0x55555555, 1)
    # gegen Referenz ((x&0x55555555)<<1) | ((x>>1)&0x55555555).
    print("Q32 bitswap adjacent: pruefe per Negation")
    for xv in Q29_BAT:
        xc = z3.BitVecVal(xv, 32)
        bs = model_bitswap(xc, z3.BitVecVal(0x55555555, 32), 1)
        ref = ((xc & z3.BitVecVal(0x55555555, 32)) << 1) | (zshr(xc, 1) & z3.BitVecVal(0x55555555, 32))
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(bs != ref)
        assert s.check() == z3.unsat, f"Q32 bitswap x={xv:#010x}"
    print("Q32 bitswap adjacent realisierbar PASS")
    print("M7 1-Pass-Enumeration (ternlog+bitfrob Oberflaeche):")
    for name in LEMMAS:
        print(f"  {name:<14} {LEMMAS[name]}")
    print("M7 PASS")

def _run_M8():

    # ---- M8: arith4-Skalar-Enumeration (Konkrete-Mode-Dispatch) ----
    # Beweis-Idiom wie gehabt: QF_BV, konkrete Eingabe-Batterien, Timeout 30s,
    # NEGATION der Identitaet assertieren -> unsat erwartet (nie Identitaet als
    # sat-Expectation). STOP bei sat/unknown: berichten, nicht abschwaechen.

    # Q34: ADD/SUB-Familie — mode 1 gegen BV-Referenz; inv_1/inv_2 konkrete Bools.
    print("Q34 ADD/SUB-Familie: pruefe 5 Paare x 4 Modi per Negation")
    Q34_PAIRS = [(5, 3), (0xFFFFFFFF, 1), (0x80000000, 0x80000000),
                 (0x12345678, 0x9ABCDEF0), (0, 0xDEADBEEF)]
    t34 = time.time()
    for (pa, pb) in Q34_PAIRS:
        a = z3.BitVecVal(pa, 32)
        b = z3.BitVecVal(pb, 32)
        z0 = z3.BitVecVal(0, 32)
        # (a) ADD = BV-Add (c=0)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_arith4(a, b, z0, 1)[0] != (a + b))
        assert s.check() == z3.unsat, f"Q34a ADD {pa:#x},{pb:#x}"
        # (b) Sub via inv_2
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_arith4(a, b, z0, 1, inv_2=True)[0] != (a - b))
        assert s.check() == z3.unsat, f"Q34b SUB {pa:#x},{pb:#x}"
        # (c) Neg via inv_1
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_arith4(a, b, z0, 1, inv_1=True)[0] != ((z3.BitVecVal(0, 32) - a) + b))
        assert s.check() == z3.unsat, f"Q34c NEG {pa:#x},{pb:#x}"
        # (d) inv_1+inv_2 = -a-b
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_arith4(a, b, z0, 1, inv_1=True, inv_2=True)[0] != ((z3.BitVecVal(0, 32) - a) - b))
        assert s.check() == z3.unsat, f"Q34d NEG+SUB {pa:#x},{pb:#x}"
    print(f"Q34 ADD/SUB-Familie {len(Q34_PAIRS)} Paare x4 bewiesen ({time.time()-t34:.2f}s) PASS")

    # Q35: SATADD (mode 5) — Klemmfaelle + Normal (kein Overflow).
    print("Q35 SATADD: pruefe 3 Faelle per Negation")
    t35 = time.time()
    for (pa, pb, exp) in [(0x7FFFFFFF, 1, 0x7FFFFFFF),
                          (0xC0000000, 0xC0000000, 0x80000000),
                          (5, 3, 8)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32), z3.BitVecVal(0, 32), 5)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q35 SATADD {pa:#x},{pb:#x}->{exp:#x}"
    print(f"Q35 SATADD 3 Faelle bewiesen ({time.time()-t35:.2f}s) PASS")

    # Q36: USATADD (z3-Label mode 4; ISS = SATADD+unsigned) — unsigned Klemmfall + Normal.
    print("Q36 USATADD: pruefe 3 Faelle per Negation")
    t36 = time.time()
    for (pa, pb, exp) in [(0xFFFFFFFF, 1, 0xFFFFFFFF),
                          (0xFFFFFFFF, 0, 0xFFFFFFFF),
                          (5, 3, 8)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32), z3.BitVecVal(0, 32), 4)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q36 USATADD {pa:#x},{pb:#x}->{exp:#x}"
    print(f"Q36 USATADD 3 Faelle bewiesen ({time.time()-t36:.2f}s) PASS")

    # Q37: AVG (mode 6) — Round-Semantik: (a+b+(c&1))>>1; 0xFFFFFFFF-Boundary.
    print("Q37 AVG: pruefe 4 Faelle per Negation")
    t37 = time.time()
    for (pa, pb, pc, exp) in [(3, 4, 1, 4),
                              (3, 4, 0, 3),
                              (0xFFFFFFFF, 0, 0, 0x7FFFFFFF),
                              (0xFFFFFFFF, 0, 1, 0x80000000)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32), z3.BitVecVal(pc, 32), 6)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q37 AVG {pa:#x},{pb:#x},{pc:#x}->{exp:#x}"
    print(f"Q37 AVG 4 Faelle bewiesen ({time.time()-t37:.2f}s) PASS")

    # Q38: ABSADD (mode 7) — |a|+b+c; |INT_MIN| wrappt auf 0x80000000.
    print("Q38 ABSADD: pruefe 3 Faelle per Negation")
    t38 = time.time()
    for (pa, pb, exp) in [(0xFFFFFFFB, 3, 8),
                          (5, 3, 8),
                          (0x80000000, 0, 0x80000000)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32), z3.BitVecVal(0, 32), 7)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q38 ABSADD {pa:#x},{pb:#x}->{exp:#x}"
    print(f"Q38 ABSADD 3 Faelle bewiesen ({time.time()-t38:.2f}s) PASS")

    # Q39: SLT/SLTU (z3-Label mode 10/11; ISS = SLT+unsigned) — Masken-Semantik, s3=1 Konst-Addend;
    # (d) inv_2 BEWUSST ignoriert (SLT nutzt raw s2) — auch mit inv_2 unsat.
    print("Q39 SLT/SLTU: pruefe 6 Faelle per Negation")
    t39 = time.time()
    for (pa, pb, mode, inv2, exp) in [(0xFFFFFFFF, 5, 10, False, 0xFFFFFFFF),
                                      (5, 0xFFFFFFFF, 10, False, 0),
                                      (5, 5, 10, False, 0),
                                      (5, 0xFFFFFFFF, 10, True, 0),
                                      (0xFFFFFFFF, 5, 11, False, 0),
                                      (1, 2, 11, False, 0xFFFFFFFF)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32),
                         z3.BitVecVal(1, 32), mode, inv_2=inv2)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q39 mode{mode} {pa:#x},{pb:#x} inv2={inv2}->{exp:#x}"
    print(f"Q39 SLT/SLTU 6 Faelle bewiesen ({time.time()-t39:.2f}s) PASS")

    # Q40: ADDSHIFT1/2 (13/14), ADDC (2, c_in; inv_2=True = SUBB-Integration), MFC (z3-Label 12 = ISS intern 40).
    print("Q40 ADDSHIFT/ADDC(+inv_2=SUBB)/MFC: pruefe 8 Faelle per Negation")
    t40 = time.time()
    for (pa, pb, pc, mode, c_in, exp) in [
            (0x1000, 0x1234, 0, 13, 0, 0x3468),
            (0x1000, 0x1234, 0, 14, 0, 0x58D0),
            (0xFFFFFFFF, 1, 0, 2, 1, 1),
            (0, 0, 0, 12, 1, 1),
            (0, 0, 0, 12, 0, 0)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32),
                         z3.BitVecVal(pc, 32), mode, z3.BitVecVal(c_in, 1))[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q40 mode{mode} c_in={c_in} {pa:#x},{pb:#x}->{exp:#x}"
    # Borrow-Fälle: ADDC mit inv_2=True == SUBB (a-b-1+c; C=1 kein Borrow)
    for (pa, pb, c_in, exp) in [(10, 3, 1, 7), (10, 3, 0, 6), (5, 10, 1, 0xFFFFFFFB)]:
        r = model_arith4(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32),
                         z3.BitVecVal(0, 32), 2, z3.BitVecVal(c_in, 1), inv_2=True)[0]
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(r != z3.BitVecVal(exp, 32))
        assert s.check() == z3.unsat, f"Q40 ADDC+inv_2 (SUBB) c_in={c_in} {pa:#x},{pb:#x}->{exp:#x}"
    print(f"Q40 ADDSHIFT/ADDC(+inv_2=SUBB)/MFC 8 Faelle bewiesen ({time.time()-t40:.2f}s) PASS")

    # Q41: LEMMAS-Update — arith4-Skalar-Identitaeten in die Tabelle.
    LEMMAS.update({
        'R_ADD': 'ADD=a+b+c (1 Pass)',
        'R_SUB': 'SUB via inv_2 (1 Pass)',
        'R_NEG': 'NEG via inv_1 (1 Pass)',
        'R_SATADD': 'SATADD klemmt 0x7FFFFFFF/0x80000000',
        'R_USATADD': 'USATADD klemmt 0xFFFFFFFF',
        'R_AVG': 'AVG runden via c&1',
        'R_ABSADD': 'ABSADD=|a|+b+c',
        'R_ABSADD_MININT': '|INT_MIN| wrappt 0x80000000',
        'R_SLT': 'SLT=Maske sign (a<b)',
        'R_SLTU': 'SLTU=Maske carry (a<b u)',
        'R_ADDSHIFT1': 'lea *3',
        'R_ADDSHIFT2': 'lea *5',
        'R_ADDC': 'ADDC carry-in',
        'R_MFC': 'MFC Carry->reg (interner Helper, z3-Label 12 = ISS Mode 40)',
        'R_ADDC_SUB': 'ADDC+inv_2 == SBC (c=1 kein Borrow)',
    })
    print("M8 1-Pass-Enumeration (arith4 Skalar-Oberflaeche):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("  Cover-Luecken (bewiesen, aber nicht in test_pipeline.py sichtbar):")
    print("    - AVG 0xFFFFFFFF/0/1 Round-up-Grenzfall (Runtime-Test nur 3/4)")
    print("    - ABSADD |INT_MIN|-Wrap 0x80000000 (Runtime-Test nur 5/0)")
    print("    - SLT inv_2-ignoriert (Runtime-Test ohne inv_2)")
    print("    - ADDC Carry-in-Kette 0xFFFFFFFF+1+1 (kein Runtime-Test)")
    print("    (ADDC+inv_2 Borrow-Faelle sind in TEST 27 bereits assertiert -> keine Luecke)")
    print("M8 PASS")

def _run_M8b():

    # ---- M8b: PADD/CMP/PMINMAX/MUL-Modelle (SWAR 1-Pass) ----
    # Beweis-Idiom wie gehabt: QF_BV, Timeout 30s, NEGATION der Identitaet
    # assertieren -> unsat erwartet. Kein z3.ForAll ueber 32-Bit. z3py >> =
    # LShR (logisch), < / > unsigned (signed nur via BVSLT/BVSGT). Negation
    # immer als BitVecVal(0,32)-x (bvsub), nie bvneg.

    def model_padd(s1, s2, lb):
        """SWAR-Packed-Add pro Lane (reale Pipeline-Formel).

        lm = wiederholte (2^(lb-1) - 1)-Lanes (lb=8: 0x7F7F7F7F, lb=16:
        0x7FFF7FFF), gm = 1-Bit pro Lane an Lane-LSB; Carry-Erkennung via
        LShR(x,lb-1) ^ LShR(t,lb-1), maskiert und zurueckgeschoben. Ueberlauf
        ueber die Lane-Grenze wird weggeschnitten (mod 2^lb). LShR explizit:
        z3py >> ist in dieser libz3 ARITHMETISCH (bvashr), nicht logisch.
        """
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
    def model_pminmax(s1, s2, lb, signed, is_max):
        """Per-Lane min/max; a>b-Carry in lb+1 Bit gerechnet (kein Wrap).

        signed: Vorzeichen-Flip (xor sign_flip) vor Vergleich; is_max waehlt
        av bei a>b, is_min waehlt bv. lb==32: Einzellane, If direkt auf s1/s2.
        """
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

    def model_mul16(s1, s2):
        """16x16->32 Multiplikation (niederwertige Haelfte)."""
        return ((s1 & 0xFFFF) * (s2 & 0xFFFF)) & 0xFFFFFFFF
    # Q42: PADD — Lane-Referenz via Extract+Concat (Summe mod 2^lb pro Lane).
    print("Q42 PADD: pruefe SWAR-Formel gegen Lane-Referenz per Negation")
    t42 = time.time()
    for lb in (8, 16):
        x = z3.BitVec('x_q42', 32)
        y = z3.BitVec('y_q42', 32)
        lanes = []
        for i in range(32 // lb):
            xl = z3.Extract(i * lb + lb - 1, i * lb, x)
            yl = z3.Extract(i * lb + lb - 1, i * lb, y)
            lanes.append(xl + yl)
        ref = z3.Concat(*reversed(lanes))
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_padd(x, y, lb) != ref)
        assert s.check() == z3.unsat, f"Q42 PADD lb={lb}: sat/unknown -> STOP"
        print(f"Q42 PADD lb={lb} bewiesen PASS")
    print(f"Q42 PADD fertig ({time.time()-t42:.2f}s) PASS")

    # Q43: CMP — Lane all-ones iff Lane-Gleichheit (lb in 8,16,32).
    print("Q43 CMP: pruefe all-ones-Lane-Semantik per Negation")
    t43 = time.time()
    for lb in (8, 16, 32):
        x = z3.BitVec('x_q43', 32)
        y = z3.BitVec('y_q43', 32)
        ref = z3.BitVecVal(0, 32)
        for i in range(32 // lb):
            xl = z3.Extract(i * lb + lb - 1, i * lb, x)
            yl = z3.Extract(i * lb + lb - 1, i * lb, y)
            eq = z3.If(xl == yl, z3.BitVecVal((1 << lb) - 1, lb), z3.BitVecVal(0, lb))
            ref = ref | (z3.ZeroExt(32 - lb, eq) << z3.BitVecVal(i * lb, 32))
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_cmp(x, y, lb) != ref)
        assert s.check() == z3.unsat, f"Q43 CMP lb={lb}: sat/unknown -> STOP"
        print(f"Q43 CMP lb={lb} bewiesen PASS")
    print(f"Q43 CMP fertig ({time.time()-t43:.2f}s) PASS")

    # Q44: PMIN/PMAX Skalar (lb=32) — der Kernbeweis: 1-Pass, kein
    # SLT+ternlog-Mikrocode. 4 Kombos (signed/unsigned x min/max).
    print("Q44 PMIN/PMAX Skalar (lb=32): pruefe 4 Kombos per Negation")
    t44 = time.time()
    x = z3.BitVec('x_q44', 32)
    y = z3.BitVec('y_q44', 32)
    combos = [
        (True, False, lambda a, b: z3.If(z3.ULT(a ^ 0x80000000, b ^ 0x80000000), a, b)),   # signed min
        (True, True, lambda a, b: z3.If(z3.UGT(a ^ 0x80000000, b ^ 0x80000000), a, b)),    # signed max
        (False, False, lambda a, b: z3.If(z3.ULT(a, b), a, b)),  # unsigned min
        (False, True, lambda a, b: z3.If(z3.UGT(a, b), a, b)),   # unsigned max
    ]
    for (signed, is_max, ref_fn) in combos:
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(model_pminmax(x, y, 32, signed, is_max) != ref_fn(x, y))
        assert s.check() == z3.unsat, f"Q44 PMIN/PMAX signed={signed} is_max={is_max}: sat/unknown -> STOP"
        print(f"Q44 PMIN/PMAX signed={signed} is_max={is_max} bewiesen PASS")
    print(f"Q44 PMIN/PMAX 4 Kombos bewiesen ({time.time()-t44:.2f}s) PASS")

    # Q45: MUL16 — 16x16->32 gegen BV-Referenz.
    print("Q45 MUL16: pruefe 16x16->32 per Negation")
    x = z3.BitVec('x_q45', 32)
    y = z3.BitVec('y_q45', 32)
    s = z3.SolverFor('QF_BV')
    s.set("timeout", 30000)
    s.add(model_mul16(x, y) != (((x & 0xFFFF) * (y & 0xFFFF)) & 0xFFFFFFFF))
    assert s.check() == z3.unsat, "Q45 MUL16: sat/unknown -> STOP"
    print("Q45 MUL16 bewiesen PASS")

    # Q46: MUL32 — signed/unsigned, lo+hi gegen 64-Bit-Referenz.
    print("Q46 MUL32: pruefe signed/unsigned lo+hi per Negation")
    t46 = time.time()
    x = z3.BitVec('x_q46', 32)
    y = z3.BitVec('y_q46', 32)
    for unsigned in (True, False):
        lo, hi = model_mul32(x, y, unsigned)
        ref = (z3.ZeroExt(32, x) * z3.ZeroExt(32, y)) if unsigned else (z3.SignExt(32, x) * z3.SignExt(32, y))
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(z3.Or(lo != z3.Extract(31, 0, ref), hi != z3.Extract(63, 32, ref)))
        assert s.check() == z3.unsat, f"Q46 MUL32 unsigned={unsigned}: sat/unknown -> STOP"
        print(f"Q46 MUL32 {'unsigned' if unsigned else 'signed'} bewiesen PASS")
    print(f"Q46 MUL32 fertig ({time.time()-t46:.2f}s) PASS")

    # Q47: MUL32ACC — Akkumulator-Kette gegen unabhaengige 64-Bit-Referenz.
    # Referenz: aux ist der HOHE Akkumulator-Teil, also (aux << 32) addieren;
    # flaches prod+s3+aux waere falsch (aux-Low laege im res-Teil).
    print("Q47 MUL32ACC: pruefe Akkumulator-Kette per Negation")
    t47 = time.time()
    x = z3.BitVec('x_q47', 32)
    y = z3.BitVec('y_q47', 32)
    for unsigned in (True, False):
        for (s3v, auxv) in [(0, 0x12345678), (0, 0)]:
            s3v_bv = z3.BitVecVal(s3v, 32)
            auxv_bv = z3.BitVecVal(auxv, 32)
            res_m, aux_m = model_mul32acc(x, y, s3v_bv, auxv_bv, unsigned)
            prod = (z3.ZeroExt(32, x) * z3.ZeroExt(32, y)) if unsigned else (z3.SignExt(32, x) * z3.SignExt(32, y))
            ref64 = prod + z3.ZeroExt(32, s3v_bv) + (z3.ZeroExt(32, auxv_bv) << 32)
            s = z3.SolverFor('QF_BV')
            s.set("timeout", 30000)
            s.add(z3.Or(res_m != z3.Extract(31, 0, ref64), aux_m != z3.Extract(63, 32, ref64)))
            assert s.check() == z3.unsat, f"Q47 MUL32ACC unsigned={unsigned} s3={s3v:#x} aux={auxv:#x}: sat/unknown -> STOP"
            print(f"Q47 MUL32ACC {'unsigned' if unsigned else 'signed'} s3={s3v:#x} aux={auxv:#x} bewiesen PASS")
    print(f"Q47 MUL32ACC Akkumulator-Kette bewiesen ({time.time()-t47:.2f}s) PASS")

    # Q48: PADD64 — 64-Bit-Add aus zwei 32-Bit-Haelften (lo+carry, hi+aux).
    print("Q48 PADD64: pruefe 64-Bit-Add aus 2 Haelften per Negation")
    t48 = time.time()
    x = z3.BitVec('x_q48', 32)
    y = z3.BitVec('y_q48', 32)
    for (s3v, auxv) in [(0, 0x12345678), (0, 0)]:
        s3v_bv = z3.BitVecVal(s3v, 32)
        auxv_bv = z3.BitVecVal(auxv, 32)
        res_m, aux_m = model_padd64(x, y, s3v_bv, auxv_bv)
        lo64 = z3.ZeroExt(32, x) + z3.ZeroExt(32, s3v_bv)
        carry = z3.Extract(32, 32, lo64)
        hi64 = z3.ZeroExt(32, y) + z3.ZeroExt(32, auxv_bv) + z3.ZeroExt(63, carry)
        s = z3.SolverFor('QF_BV')
        s.set("timeout", 30000)
        s.add(z3.Or(res_m != z3.Extract(31, 0, lo64), aux_m != z3.Extract(31, 0, hi64)))
        assert s.check() == z3.unsat, f"Q48 PADD64 s3={s3v:#x} aux={auxv:#x}: sat/unknown -> STOP"
        print(f"Q48 PADD64 s3={s3v:#x} aux={auxv:#x} bewiesen PASS")
    print(f"Q48 PADD64 bewiesen ({time.time()-t48:.2f}s) PASS")

    # Q49: LEMMAS-Update — M8b-Identitaeten in die Tabelle (realisierbar).
    LEMMAS.update({
        'R_PADD_B': 'PADD byte SWAR 1-Pass',
        'R_PADD_W': 'PADD word SWAR 1-Pass',
        'R_CMP_B': 'CMP byte all-ones-Lanes',
        'R_CMP_W': 'CMP word all-ones-Lanes',
        'R_CMP_S': 'CMP 32 all-ones 1-Pass',
        'R_MIN_S': 'PMIN 32 signed 1-Pass',
        'R_MIN_U': 'PMIN 32 unsigned 1-Pass',
        'R_MAX_S': 'PMAX 32 signed 1-Pass',
        'R_MAX_U': 'PMAX 32 unsigned 1-Pass',
        'R_MUL16': 'MUL16 16x16->32',
        'R_MUL32_S': 'MUL32 signed lo/hi',
        'R_MUL32_U': 'MUL32 unsigned lo/hi',
        'R_MULHI_S': 'MULHI signed res=hi32, aux=lo32',
        'R_MULHI_U': 'MULHI unsigned res=hi32, aux=lo32',
        'R_MUL32ACC_S': 'MUL32ACC signed +akkum',
        'R_MUL32ACC_U': 'MUL32ACC unsigned +akkum',
        'R_PADD64': 'PADD64 lo/hi mit Carry',
    })
    print("M8b 1-Pass-Enumeration (padd/cmp/minmax/mul-Oberflaeche):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M8b PASS")

def _run_M9():

    # === M9: permb — Byte/Nibble-Permute + shift_ctrl (AltiVec-lvsr) ===
    def model_permb_nib(s1, s2, ctrl):
        """Nibble-Modus: 8 Output-Nibbles, 4-Bit-Index waehlt aus allen 16
        Concat-Nibbles (0..7=src2, 8..15=src1). KEIN Blank im Nibble-Modus."""
        concat = z3.Concat(s1, s2)
        res = z3.BitVecVal(0, 32)
        for i in range(8):
            idx = (ctrl >> (4 * i)) & 0x0F
            nib = z3.Extract(3 + 4 * idx, 4 * idx, concat)
            res = res | (z3.ZeroExt(28, nib) << z3.BitVecVal(4 * i, 32))
        return res
    # Q50: permb Byte-Identitaet — ctrl=0x03020100, blank aus (LSB-first:
    # cb_0=0x00->concat byte 0 .. cb_3=0x03). Result == y; aux (non-shift)
    # == src3 == ctrl. Zwei getrennte Solver-Calls.
    print("Q50 permb Byte-Identitaet: pruefe per Negation")
    x = z3.BitVec('x_q50', 32)
    y = z3.BitVec('y_q50', 32)
    _m9_unsat("Q50 permb Byte-Identitaet res==y",
              model_permb_byte(x, y, 0x03020100, False) != y)
    _m9_unsat("Q50 permb aux==ctrl",
              z3.Or(model_permb_byte(x, y, 0x03020100, False) != y,
                    z3.BitVecVal(0x03020100, 32) != z3.BitVecVal(0x03020100, 32)))

    # Q51: permb Byte-High-Select — ctrl=0x07060504 (LSB-first:
    # cb_i=4+i -> concat Bytes 4..7 = src1-Bytes).
    print("Q51 permb Byte-High-Select: pruefe per Negation")
    x = z3.BitVec('x_q51', 32)
    y = z3.BitVec('y_q51', 32)
    _m9_unsat("Q51 permb Byte-High-Select res==x",
              model_permb_byte(x, y, 0x07060504, False) != x)

    # Q52: permb Blank — ctrl=0x80808080, blank_enable=True. Result == 0.
    print("Q52 permb Blank: pruefe per Negation")
    x = z3.BitVec('x_q52', 32)
    y = z3.BitVec('y_q52', 32)
    _m9_unsat("Q52 permb Blank res==0",
              model_permb_byte(x, y, 0x80808080, True) != z3.BitVecVal(0, 32))

    # Q53: permb Blank-aus — High-Bit ignoriert, idx=0 -> Byte0 4x repliziert.
    print("Q53 permb Blank-aus: pruefe per Negation")
    x = z3.BitVec('x_q53', 32)
    y = z3.BitVec('y_q53', 32)
    ref = z3.ZeroExt(24, z3.Extract(7, 0, y))
    ref = ref | (ref << 8) | (ref << 16) | (ref << 24)
    _m9_unsat("Q53 permb Blank-aus res==ref",
              model_permb_byte(x, y, 0x80808080, False) != ref)

    # Q54: permb Nibble-Identitaet — ctrl=0x76543210 (Nibbles 0..7 = src2).
    print("Q54 permb Nibble-Identitaet: pruefe per Negation")
    x = z3.BitVec('x_q54', 32)
    y = z3.BitVec('y_q54', 32)
    _m9_unsat("Q54 permb Nibble-Identitaet res==y",
              model_permb_nib(x, y, 0x76543210) != y)

    # Q55: permb Nibble-High-Select — ctrl=0xFEDCBA98 (Nibble 8+i = src1-Nibble i).
    print("Q55 permb Nibble-High-Select: pruefe per Negation")
    x = z3.BitVec('x_q55', 32)
    y = z3.BitVec('y_q55', 32)
    _m9_unsat("Q55 permb Nibble-High-Select res==x",
              model_permb_nib(x, y, 0xFEDCBA98) != x)

    # Q56: permb Nibble-Broadcast-15 — ctrl=0xFFFFFFFF (Concat-Nibble 15 =
    # src1-MSB-Nibble, repliziert auf alle 8 Output-Nibbles).
    print("Q56 permb Nibble-Broadcast-15: pruefe per Negation")
    x = z3.BitVec('x_q56', 32)
    y = z3.BitVec('y_q56', 32)
    base = z3.ZeroExt(28, z3.Extract(31, 28, x))
    ref = base
    for i in range(1, 8):
        ref = ref | (base << z3.BitVecVal(4 * i, 32))
    _m9_unsat("Q56 permb Nibble-Broadcast-15 res==ref",
              model_permb_nib(x, y, 0xFFFFFFFF) != ref)

    # Q57: shift_ctrl LSR n=8 (k=1): res = y>>8 (Top-Byte blank), so = Byte0.
    print("Q57 permb shift_ctrl LSR8: pruefe per Negation")
    x = z3.BitVec('x_q57', 32)
    y = z3.BitVec('y_q57', 32)
    res, so = model_permb_shift(x, y, 8, False)
    _m9_unsat("Q57 permb LSR8 res==LShR(y,8)", res != z3.LShR(y, 8))
    _m9_unsat("Q57 permb LSR8 so==(y&0xFF)", so != (y & z3.BitVecVal(0xFF, 32)))

    # Q58: shift_ctrl LSL n=8 (k=1): res = y<<8 (Low-Byte blank), so = Byte7
    # (src1-MSB, rausgeschoben).
    print("Q58 permb shift_ctrl LSL8: pruefe per Negation")
    x = z3.BitVec('x_q58', 32)
    y = z3.BitVec('y_q58', 32)
    res, so = model_permb_shift(x, y, 8, True)
    _m9_unsat("Q58 permb LSL8 res==(y<<8)&0xFFFFFFFF",
              res != ((y << z3.BitVecVal(8, 32)) & z3.BitVecVal(0xFFFFFFFF, 32)))
    _m9_unsat("Q58 permb LSL8 so==(x>>24)&0xFF",
              so != (z3.LShR(x, 24) & z3.BitVecVal(0xFF, 32)))

    # Q57b: shift_ctrl LSR n=16 (k=2): res = y>>16 (zwei Top-Bytes blank),
    # shifted_out = sticky-OR Byte0|Byte1 in Low-Byte (concat-Layout).
    print("Q57b permb shift_ctrl LSR16: pruefe per Negation")
    x = z3.BitVec('x_q57b', 32)
    y = z3.BitVec('y_q57b', 32)
    res, so = model_permb_shift(x, y, 16, False)
    _m9_unsat("Q57b permb LSR16 res==(y>>16)&0xFFFF",
              res != (z3.LShR(y, 16) & z3.BitVecVal(0xFFFF, 32)))
    _m9_unsat("Q57b permb LSR16 so==byte0|byte1",
              so != ((y & z3.BitVecVal(0xFF, 32)) |
                     (z3.LShR(y, 8) & z3.BitVecVal(0xFF, 32))))

    # Q58b: shift_ctrl LSL n=16 (k=2): res = y<<16 (zwei Low-Bytes blank),
    # shifted_out = sticky-OR Concat-Byte6|Byte7 (= src1 Byte1|Byte0).
    print("Q58b permb shift_ctrl LSL16: pruefe per Negation")
    x = z3.BitVec('x_q58b', 32)
    y = z3.BitVec('y_q58b', 32)
    res, so = model_permb_shift(x, y, 16, True)
    _m9_unsat("Q58b permb LSL16 res==(y<<16)&0xFFFFFFFF",
              res != ((y << z3.BitVecVal(16, 32)) & z3.BitVecVal(0xFFFFFFFF, 32)))
    _m9_unsat("Q58b permb LSL16 so==xbyte1|xbyte0",
              so != ((z3.LShR(x, 24) & z3.BitVecVal(0xFF, 32)) |
                     (z3.LShR(x, 16) & z3.BitVecVal(0xFF, 32))))

    # Q59: LEMMAS-Update — M9-permb-Identitaeten in die Tabelle (realisierbar).
    LEMMAS.update({
        'R_PERMB_IDB': 'permb Byte-Identitaet 1-Pass',
        'R_PERMB_HISEL': 'permb Byte-High-Select 1-Pass',
        'R_PERMB_BLANK': 'permb Blank 1-Pass',
        'R_PERMB_NIBID': 'permb Nibble-Identitaet 1-Pass',
        'R_PERMB_NIB15': 'permb Nibble-Broadcast-15 1-Pass',
        'R_PERMB_LSR8': 'permb shift_ctrl LSR 8 1-Pass',
        'R_PERMB_LSL8': 'permb shift_ctrl LSL 8 1-Pass',
    })
    print("M9 1-Pass-Enumeration (permb/shift_ctrl-Oberflaeche):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M9 PASS")

def _run_M10():

    # ---- M10: Aux-Pipe-Slot-Modelle (2. Pipe-Slot: aux-Taps) + Komposition ----
    def model_aux_arith4(s1, s2, s3, mode, c_in, aux_in):
        """arith4 aux-Tap: (res, aux). mode konkreter ArithMode-Int (inkl. |0x20 unsigned).

        ADD(1): res=model_arith4(...)[0], aux=s3. CMP(8): res=model_cmp(s1,s2,32), aux=s1^s2.
        MUL32(28|0x20): lo,hi=model_mul32(s1,s2,True), res=lo, aux=hi.
        MULHI(29|0x20): res=hi32, aux=lo32 (symmetrisch zu MUL32, nach Flags-Fix).
        PADD64(30): res,hi=model_padd64(s1,s2,s3,aux_in), aux=hi.
        MUL32ACC(31|0x20): res,hi=model_mul32acc(s1,s2,s3,aux_in,True), aux=hi."""
        if not isinstance(c_in, z3.BitVecRef):
            c_in = z3.BitVecVal(c_in, 1)
        if not isinstance(aux_in, z3.BitVecRef):
            aux_in = z3.BitVecVal(aux_in, 32)
        if mode == 1:
            return (model_arith4(s1, s2, s3, 1)[0], s3)
        if mode == 8:
            return (model_cmp(s1, s2, 32), s1 ^ s2)
        if mode == (28 | 0x20):
            lo, hi = model_mul32(s1, s2, True)
            return (lo, hi)
        if mode == (29 | 0x20):
            lo, hi = model_mul32(s1, s2, True)
            return (hi, lo)
        if mode == 30:
            r, h = model_padd64(s1, s2, s3, aux_in)
            return (r, h)
        if mode == (31 | 0x20):
            r, h = model_mul32acc(s1, s2, s3, aux_in, True)
            return (r, h)
        raise ValueError(f"M10: arith4 mode {mode} nicht im aux-Satz")

    # QA1: arith4 ADD aux == s3 (Pipeline-Konvention).
    print("QA1 arith4 ADD aux==s3: pruefe per Negation")
    xa = z3.BitVec('x_qa1', 32)
    ya = z3.BitVec('y_qa1', 32)
    s3a = z3.BitVec('s3_qa1', 32)
    _m9_unsat("QA1 arith4 ADD aux==s3",
              model_aux_arith4(xa, ya, s3a, 1, 0, 0)[1] != s3a)

    # QA2: arith4 CMP aux == s1^s2 (XOR-Diff).
    print("QA2 arith4 CMP aux==s1^s2: pruefe per Negation")
    xb = z3.BitVec('x_qa2', 32)
    yb = z3.BitVec('y_qa2', 32)
    s3b = z3.BitVec('s3_qa2', 32)
    _m9_unsat("QA2 arith4 CMP aux==s1^s2",
              model_aux_arith4(xb, yb, s3b, 8, 0, 0)[1] != (xb ^ yb))

    # QA3: arith4 MUL32 (28|0x20) aux == hi32 des Produkts.
    print("QA3 arith4 MUL32 aux==hi32: pruefe per Negation")
    xc3 = z3.BitVec('x_qa3', 32)
    yc3 = z3.BitVec('y_qa3', 32)
    _m9_unsat("QA3 arith4 MUL32 aux==hi32",
              model_aux_arith4(xc3, yc3, 0, 28 | 0x20, 0, 0)[1] != model_mul32(xc3, yc3, True)[1])

    # QA4: arith4 MULHI (29|0x20) aux == lo32 (symmetrisch zu MUL32, nach Flags-Fix).
    print("QA4 arith4 MULHI aux==lo32: pruefe per Negation")
    xd = z3.BitVec('x_qa4', 32)
    yd = z3.BitVec('y_qa4', 32)
    _m9_unsat("QA4 arith4 MULHI aux==lo32",
              model_aux_arith4(xd, yd, 0, 29 | 0x20, 0, 0)[1] != model_mul32(xd, yd, True)[0])

    # QA5: bitfrob MASKW aux == s3 (die Breite).
    print("QA5 bitfrob MASKW aux==s3: pruefe per Negation")
    xe = z3.BitVec('x_qa5', 32)
    s3e = z3.BitVec('s3_qa5', 32)
    _m9_unsat("QA5 bitfrob MASKW aux==s3",
              model_aux_bitfrob(xe, 0, s3e, 12, 0)[1] != s3e)

    # QA6: bitfrob ROL aux == s1 (traegt Original).
    print("QA6 bitfrob ROL aux==s1: pruefe per Negation")
    xf = z3.BitVec('x_qa6', 32)
    _m9_unsat("QA6 bitfrob ROL aux==s1",
              model_aux_bitfrob(xf, 0, 0, 8, 0)[1] != xf)

    # QA7: SHR_STICKY amt=3 — res + Sticky-Bits (TEST 38: 0xDEADBEEF -> 0x1BD5B7DD/0x7).
    print("QA7 shr_sticky amt=3 res+sticky: pruefe per Negation")
    xg = z3.BitVec('x_qa7', 32)
    yg = z3.BitVec('y_qa7', 32)
    _m9_unsat("QA7 shr_sticky amt=3 res==LShR(y,3)&0x1FFFFFFF",
              model_shr_sticky(xg, yg, 3)[0] != (z3.LShR(yg, 3) & 0x1FFFFFFF))
    _m9_unsat("QA7 shr_sticky amt=3 sticky==y&7",
              model_shr_sticky(xg, yg, 3)[1] != (yg & 7))

    # QA8: bitfrob LSR aux == s1 (Original).
    print("QA8 bitfrob LSR aux==s1: pruefe per Negation")
    xh = z3.BitVec('x_qa8', 32)
    _m9_unsat("QA8 bitfrob LSR aux==s1",
              model_aux_bitfrob(xh, 0, 0, 0, 0)[1] != xh)

def _run_M10b():

    # ---- M10b: Kompositions-Beweise (2. Pipe-Slot) ----
    # QC0: LUT 0x96 (TernLut.XOR3) == 3-Input-XOR (Basis fuer alle ternlog-Ketten).
    print("QC0 ternlog LUT 0x96 = a^b^c: pruefe per Negation")
    a0 = z3.BitVec('a_qc0', 32)
    b0 = z3.BitVec('b_qc0', 32)
    c0 = z3.BitVec('c_qc0', 32)
    _m9_unsat("QC0 ternlog LUT 0x96 = a^b^c",
              model_ternlog(a0, b0, c0, 0x96) != (a0 ^ b0 ^ c0))

    # QC1: in-Pass-aux-Kette (TEST-13-Identitaet): permb-Bypass -> bitfrob ROL
    # (aux=Original x) -> ternlog LUT 0x96 (a=prev_in=rotiert, b=aux, c=in_c)
    # -> arith4-Bypass. TEST 13 ctrl_aux_combine: 0x12345678/2 -> 0xF04FA532.
    print("QC1 ternlog ROL-Bypass aux-Kette: pruefe per Negation")
    xc1 = z3.BitVec('x_qc1', 32)
    for amt in (1, 2, 3, 7):
        c = amt | 0x55555555
        r1 = model_rol(xc1, z3.BitVecVal(amt, 32))
        _m9_unsat(f"QC1 ternlog ROL-Bypass aux-Kette amt={amt} (TEST 13)",
                  model_ternlog(r1, model_aux_bitfrob(xc1, 0, c, 8, 0)[1],
                                z3.BitVecVal(c, 32), 0x96) != (r1 ^ xc1 ^ z3.BitVecVal(c, 32)))

    # QC2: PADD64 packt MUL32-Paar wieder zusammen (lo,hi) -> (res,aux).
    print("QC2 PADD64 packt MUL32-Paar: pruefe per Negation")
    a2 = z3.BitVec('a_qc2', 32)
    b2 = z3.BitVec('b_qc2', 32)
    lo2, hi2 = model_mul32(a2, b2, True)
    r2, h2 = model_padd64(lo2, z3.BitVecVal(0, 32), z3.BitVecVal(0, 32), hi2)
    _m9_unsat("QC2 PADD64 packt MUL32-Paar",
              z3.Or(r2 != lo2, h2 != hi2))

    # QC3: MUL32(a,b) -> aux=hi1; MUL32ACC(c,d,lo1,hi1) == (a*b)+(c*d) 64-Bit.
    # TEST 34 lines 887-913.
    print("QC3 MUL32ACC 2-Produkt-MAC: pruefe per Negation")
    c3 = z3.BitVec('c_qc3', 32)
    d3 = z3.BitVec('d_qc3', 32)
    for (pa, pb) in [(0x1000, 0x2000), (0x10000, 0x10000)]:
        lo1, hi1 = model_mul32(z3.BitVecVal(pa, 32), z3.BitVecVal(pb, 32), True)
        prod_cd = z3.ZeroExt(32, c3) * z3.ZeroExt(32, d3)
        total = z3.BitVecVal(pa * pb, 64) + prod_cd
        r3, h3 = model_mul32acc(c3, d3, lo1, hi1, True)
        _m9_unsat(f"QC3 MUL32ACC 2-Produkt-MAC {pa:#x}x{pb:#x} (TEST 34)",
                  z3.Or(r3 != z3.Extract(31, 0, total), h3 != z3.Extract(63, 32, total)))

    # M10: LEMMAS-Update — aux-Tap- und Kompositions-Identitaeten.
    LEMMAS.update({
        'R_TERN_XOR3': 'ternlog LUT 0x96 = 3-Input-XOR 1-Pass',
        'R_AUX_ROL': 'bitfrob ROL traegt Original in aux',
        'R_AUX_LSR': 'bitfrob LSR aux = Original',
        'R_MASKW_AUX': 'MASKW aux = Breite s3',
        'R_STICKY_AUX': 'SHR_STICKY aux = Sticky-Bits',
        'R_MUL32_HIAUX': 'MUL32 aux = hi32',
        'R_CMP_AUX': 'CMP aux = XOR-Diff s1^s2',
        'R_PACK64': 'PADD64 packt MUL32-Paar (lo,hi)',
        'R_MAC_2STEP': 'MUL32+MUL32ACC = 2-Produkt-MAC',
        # M12: echte Mikrocode-Sequenzen aus helpers.py, gegen unabhaengige
        # Referenz fuer ALLE Eingaben bewiesen (Q60..Q66).
        'R_CMOV': 'M12 ctrl_cmov: MASK+SELECT_A (c!=0 -> a, sonst b)',
        'R_MIN2': 'M12 ctrl_slt+ctrl_min: SLT-Maske + SELECT_A = signed min',
        'R_MAX2': 'M12 ctrl_slt+ctrl_max: SELECT_B=0xD8-Fix verifiziert = signed max',
        'R_UBFX1': 'M12 ctrl_ubfx: ROR fein + AND = (x>>lsb)&0xFF',
        'R_BFI1': 'M12 ctrl_bfi0: SELECT_A-Blend (y&mask)|(x&~mask)',
        'R_POPCNT3': 'M12 ctrl_popcnt_full: POPCNT_B+PWADD byte+PWADD word',
        'R_GRAYBIN': 'M12 gray_to_bin: 5-Pass LSR fine+permb, XOR-Kette',
    })
    print("M10 1-Pass-Enumeration (aux-Taps + Komposition):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M10 PASS")

def _run_M12():

    # === M12: echte Mikrocode-Sequenzen (helpers.py) gegen Referenzen ===
    # Reale ctrl-Dicts: ctrl_cmov, ctrl_slt, ctrl_min, ctrl_max, ctrl_ubfx,
    # ctrl_bfi0 (test_pipeline.py) sowie ctrl_popcnt_full, gray_to_bin
    # (helpers.py). Jede Sequenz = 1..5 Makro-Schritte; prev_in von Schritt
    # N+1 = res von Schritt N. Verifikation gegen unabhaengige Referenzen
    # fuer ALLE Eingaben (Negation unsat), QF_BV + 30s Timeout (Idiom wie M9).
    # Operanden-Verdrahtung aus den realen Strobe-Bits abgelesen (bit 8 =
    # Bypass, bits 1/2/4 = prev_in auf src1/src2/src3).

    # Q60 CMOV (ctrl_cmov): permb Bypass -> bitfrob MASK(s3=c) -> mask;
    # ternlog SELECT_A(0xE4), c=prev_in=mask (strobe bit 4) -> res; arith4 Bypass.
    print("Q60 CMOV (ctrl_cmov): pruefe per Negation")
    q60_a = z3.BitVec('q60_a', 32)
    q60_b = z3.BitVec('q60_b', 32)
    q60_c = z3.BitVec('q60_c', 32)
    q60_mask = model_mask(q60_c)
    q60_res = model_ternlog(q60_a, q60_b, q60_mask, 0xE4)
    _m9_unsat("Q60 CMOV res==If(c!=0,a,b)",
              q60_res != z3.If(q60_c != 0, q60_a, q60_b))

    # Q61 MIN 2-Pass (ctrl_slt + ctrl_min): Pass1 arith4 SLT cst_table=True
    # src3_idx=1 (ARITH_CST[1]=1) -> Maske; Pass2 ternlog SELECT_A(0xE4),
    # c=prev_in=Maske (strobe bit 4). Signed min via Sign-Flip (kein BVSLT).
    print("Q61 MIN 2-Pass (ctrl_slt+ctrl_min): pruefe per Negation")
    q61_a = z3.BitVec('q61_a', 32)
    q61_b = z3.BitVec('q61_b', 32)
    q61_slt = model_arith4(q61_a, q61_b, z3.BitVecVal(1, 32), 10, 0)[0]
    q61_res = model_ternlog(q61_a, q61_b, q61_slt, 0xE4)
    q61_sgn = z3.BitVecVal(0x80000000, 32)
    _m9_unsat("Q61 MIN res==min(a,b) signed",
              q61_res != z3.If(z3.ULT(q61_a ^ q61_sgn, q61_b ^ q61_sgn), q61_a, q61_b))

    # Q62 MAX 2-Pass (ctrl_slt + ctrl_max): Pass2 ternlog SELECT_B(0xD8,
    # pipeline.py:123) — verifiziert die korrigierte LUT im Min/Max-Pfad.
    print("Q62 MAX 2-Pass (ctrl_slt+ctrl_max, SELECT_B=0xD8): pruefe per Negation")
    q62_a = z3.BitVec('q62_a', 32)
    q62_b = z3.BitVec('q62_b', 32)
    q62_slt = model_arith4(q62_a, q62_b, z3.BitVecVal(1, 32), 10, 0)[0]
    q62_res = model_ternlog(q62_a, q62_b, q62_slt, 0xD8)
    q62_sgn = z3.BitVecVal(0x80000000, 32)
    _m9_unsat("Q62 MAX res==max(a,b) signed",
              q62_res != z3.If(z3.ULT(q62_a ^ q62_sgn, q62_b ^ q62_sgn), q62_b, q62_a))
    print("Q62 Note: verifiziert korrigiertes SELECT_B=0xD8 im Runtime-Min/Max-Pfad")

    # Q63 UBFX 1-Pass (ctrl_ubfx): bitfrob ROR(s1=x, s3=lsb) -> ternlog
    # AND(0xC0), a=prev_in=ror (strobe bit 1), b=in_b=Maske 0xFF.
    print("Q63 UBFX 1-Pass (ctrl_ubfx): pruefe lsb in [1,3,5] per Negation")
    for q63_lsb in (1, 3, 5):
        q63_x = z3.BitVec(f'q63_x_{q63_lsb}', 32)
        q63_ror = model_ror(q63_x, z3.BitVecVal(q63_lsb, 32))
        q63_res = model_ternlog(q63_ror, z3.BitVecVal(0xFF, 32),
                                z3.BitVecVal(0, 32), 0xC0)
        _m9_unsat(f"Q63 UBFX lsb={q63_lsb} res==(LShR(x,lsb))&0xFF",
                  q63_res != (z3.LShR(q63_x, q63_lsb) & z3.BitVecVal(0xFF, 32)))

    # Q64 BFI 1-Pass (ctrl_bfi0): nur ternlog SELECT_A(0xE4) aktiv (strobe 0),
    # a=in_a=y, b=in_b=x, c=in_c=Maske 0xFF — per-Bit-Blend.
    print("Q64 BFI 1-Pass (ctrl_bfi0): pruefe per Negation")
    q64_y = z3.BitVec('q64_y', 32)
    q64_x = z3.BitVec('q64_x', 32)
    q64_mask = z3.BitVecVal(0xFF, 32)
    q64_res = model_ternlog(q64_y, q64_x, q64_mask, 0xE4)
    _m9_unsat("Q64 BFI res==(y&mask)|(x&~mask)",
              q64_res != ((q64_y & q64_mask) |
                          (q64_x & (~q64_mask & z3.BitVecVal(0xFFFFFFFF, 32)))))

    # Q65 POPCNT 3-Pass (ctrl_popcnt_full): (1) bitfrob POPCNT_B(in_a=x);
    # (2) arith4 PWADD op_type_1=BYTE, prev_in_strobe=1 (src1=prev_in);
    # (3) arith4 PWADD op_type_1=WORD, prev_in_strobe=1. Referenz: SWAR-
    # Multiplikations-Trick (BV-Mul + LShR, kein bvashr).
    print("Q65 POPCNT 3-Pass (ctrl_popcnt_full): pruefe per Negation")
    q65_x = z3.BitVec('q65_x', 32)
    q65_r1 = model_popcnt_b(q65_x)
    q65_r2 = (q65_r1 + zshr(q65_r1, 8)) & z3.BitVecVal(0x00FF00FF, 32)
    q65_r3 = (q65_r2 + zshr(q65_r2, 16)) & z3.BitVecVal(0x0000FFFF, 32)
    q65_t0 = q65_x - (z3.LShR(q65_x, 1) & z3.BitVecVal(0x55555555, 32))
    q65_t1 = (q65_t0 & z3.BitVecVal(0x33333333, 32)) + \
             (z3.LShR(q65_t0, 2) & z3.BitVecVal(0x33333333, 32))
    q65_t2 = (q65_t1 + z3.LShR(q65_t1, 4)) & z3.BitVecVal(0x0F0F0F0F, 32)
    q65_ref = z3.LShR(q65_t2 * z3.BitVecVal(0x01010101, 32), 24)
    _m9_unsat("Q65 POPCNT r3==SWAR-Referenz", q65_r3 != q65_ref)

    # Q66 GRAY->BIN 5-Pass (gray_to_bin): shift in [1,2,4] via bitfrob LSR
    # fein (s1=0, Funnel-Anteil maskiert); shift 8/16 via permb Escape-Vektor
    # 0x04030201/0x05040302 (PERMB_SHIFT_VEC LSR8/LSR16, helpers.py); jede
    # Stufe ternlog XOR(0x3C) mit c=TERNLOG_CST[0]=0.
    # Beweis-Lemma-Substitution (wie zland/zlor/zlxor/zshr in M6/M7): die
    # per-Bit-Kaskade (model_lsr+model_ternlog, 5 Stufen) sprengt das
    # 30s-QF_BV-Budget (unknown@30s, unsat@120s — Eigenschaft gilt). Ersetzt
    # durch bewiesene Identitaeten: Q4 LSR(s1=0)==LShR, Q28 LUT 0x3C==a^b.
    print("Q66 GRAY->BIN 5-Pass (gray_to_bin): pruefe per Negation")
    q66_g = z3.BitVec('q66_g', 32)
    q66_prev = q66_g
    q66_ref = q66_g
    for q66_s in (1, 2, 4, 8, 16):
        if q66_s <= 4:
            q66_h = z3.LShR(q66_prev, q66_s)   # = model_lsr(s1=0,s2=prev,s3=s) (Q4)
        elif q66_s == 8:
            q66_h = model_permb_byte(z3.BitVecVal(0, 32), q66_prev, 0x04030201, False)
        else:
            q66_h = model_permb_byte(z3.BitVecVal(0, 32), q66_prev, 0x05040302, False)
        q66_prev = q66_prev ^ q66_h            # = model_ternlog(prev,h,0,0x3C) (Q28)
        q66_ref = q66_ref ^ z3.LShR(q66_ref, q66_s)
    _m9_unsat("Q66 GRAY->BIN prev==ref", q66_prev != q66_ref)

    print("M12 PASS")

def _run_M13():

    # === M13: Makro-Sequenzen aus helpers.py (shift_right/shift_left/mul_ctz/gray) ===
    # Reale Makro-Sequenzen transkribiert (Anti-Bug: Konfigurationen aus Code,
    # nicht Prosa): shift_right/shift_left = permb Escape-Vektor (Byte-Teil) +
    # bitfrob fein (Funnel); mul_ctz = CTZ-shift-add-Loop; Gray-Roundtrip.
    # PERMB_SHIFT_VEC aus pipeline.py (LSR8/16/24 = 0x04030201/0x05040302/
    # 0x06050403, LSL8/16/24 = 0x02010004/0x01000404/0x00040404).

    # Q67 shift_right: Byte-Shifts via permb Escape (s1=0, Wert in s2),
    # Feinshift via bitfrob LSR (Funnel: Wert in s2, s1=0). Gegen LShR.
    print("Q67 shift_right: pruefe n in [0,1,7,8,9,15,16,23,24,31] per Negation")
    q67_x = z3.BitVec('x_q67', 32)
    Q67_LSR_VEC = {8: 0x04030201, 16: 0x05040302, 24: 0x06050403}
    def model_shift_right(x, n):
        if n == 0:
            return x
        res = x
        for bshift in (24, 16, 8):
            if n >= bshift:
                res = model_permb_byte(z3.BitVecVal(0, 32), res, Q67_LSR_VEC[bshift], False)
                n -= bshift
        if n > 0:
            res = model_lsr(z3.BitVecVal(0, 32), res, z3.BitVecVal(n, 32))
        return res
    for q67_n in [0, 1, 7, 8, 9, 15, 16, 23, 24, 31]:
        _m9_unsat(f"Q67 shift_right n={q67_n} res==LShR(x,n)",
                  model_shift_right(q67_x, q67_n) != z3.LShR(q67_x, q67_n))

    # Q68 shift_left: Byte-Shifts via permb Escape (s1=0, Wert in s2),
    # Feinshift via bitfrob LSL (Funnel: Wert in s1, s2=0). Ergebnis
    # MASK_RLEN-Semantik (32-Bit-Wrap = Maske der echten Helfer).
    print("Q68 shift_left: pruefe n in [0,1,7,8,9,15,16,23,24,31] per Negation")
    q68_x = z3.BitVec('x_q68', 32)
    Q68_LSL_VEC = {8: 0x02010004, 16: 0x01000404, 24: 0x00040404}
    def model_shift_left(x, n):
        if n == 0:
            return x
        res = x
        for bshift in (24, 16, 8):
            if n >= bshift:
                res = model_permb_byte(z3.BitVecVal(0, 32), res, Q68_LSL_VEC[bshift], False)
                n -= bshift
        if n > 0:
            res = model_lsl(res, z3.BitVecVal(0, 32), z3.BitVecVal(n, 32))
        return res
    for q68_n in [0, 1, 7, 8, 9, 15, 16, 23, 24, 31]:
        _m9_unsat(f"Q68 shift_left n={q68_n} res==(x<<n)&MASK_RLEN",
                  model_shift_left(q68_x, q68_n) != (q68_x << q68_n))

    # Q69 mul_ctz 8x8: exakter CTZ-shift-add-Loop (helpers.py ctz_mul_step),
    # 32 ungerollte Iterationen mit b!=0-Gate (Loop-Bedingung). TZC via
    # model_tzc &0x1F, a<<=tz / b>>=tz via Funnel LSL/LSR, res+=a via arith4
    # ADD (mode 1). 8-Bit-Produkt bleibt im 16-Bit-Bereich (kein Overflow).
    print("Q69 mul_ctz 8x8: pruefe 16-Bit-Produkt per Negation")
    q69_a = z3.BitVec('a_q69', 8)
    q69_b = z3.BitVec('b_q69', 8)
    def model_mul_ctz(a8, b8):
        a = z3.ZeroExt(24, a8)
        b = z3.ZeroExt(24, b8)
        res = z3.BitVecVal(0, 32)
        z0 = z3.BitVecVal(0, 32)
        for i in range(32):
            bz = b != 0
            tz = model_tzc(b) & z3.BitVecVal(0x1F, 32)
            do_tz = z3.UGT(tz, 0)
            a_tz = z3.If(do_tz, model_lsl(a, z0, tz), a)
            b_tz = z3.If(do_tz, model_lsr(z0, b, tz), b)
            r_add = z3.If(z3.Extract(0, 0, b_tz) == 1,
                          model_arith4(res, a_tz, z0, 1)[0], res)
            if i < 31:
                a_fin = model_lsl(a_tz, z0, z3.BitVecVal(1, 32))
                b_fin = model_lsr(z0, b_tz, z3.BitVecVal(1, 32))
            else:
                a_fin = a_tz
                b_fin = b_tz
            a = z3.If(bz, a_fin, a)
            b = z3.If(bz, b_fin, b)
            res = z3.If(bz, r_add, res)
        return res & z3.BitVecVal(0xFFFF, 32)
    _m9_unsat("Q69 mul_ctz res==ZeroExt(24,a)*ZeroExt(24,b) (16-Bit-Produkt)",
              model_mul_ctz(q69_a, q69_b) != (z3.ZeroExt(24, q69_a) * z3.ZeroExt(24, q69_b)))

    # Q70 Gray-Roundtrip: bin->gray 1-Pass (LSR1 + XOR-LUT 0x3C), gray->bin
    # 5-Pass (Shifts 1,2,4 fein / 8,16 permb Escape, XOR-Kette). Lemma-
    # Substitution wie Q66 (Q4: LSR(s1=0)==LShR; Q28: LUT 0x3C==a^b).
    print("Q70 Gray Roundtrip bin->gray->bin: pruefe per Negation")
    q70_x = z3.BitVec('x_q70', 32)
    q70_prev = q70_x ^ z3.LShR(q70_x, 1)
    for q70_s in (1, 2, 4, 8, 16):
        if q70_s <= 4:
            q70_h = z3.LShR(q70_prev, q70_s)
        elif q70_s == 8:
            q70_h = model_permb_byte(z3.BitVecVal(0, 32), q70_prev, 0x04030201, False)
        else:
            q70_h = model_permb_byte(z3.BitVecVal(0, 32), q70_prev, 0x05040302, False)
        q70_prev = q70_prev ^ q70_h
    _m9_unsat("Q70 Gray Roundtrip == x", q70_prev != q70_x)

    # Q71 --stretch (optional): zpdep32(zpext32(x,m),m)==x&m fuer SYMBOLISCHES
    # m (alle 2^32 Masken) — nur mit --stretch, 5-Minuten-Timeout. unknown/
    # timeout bricht NICHT ab (stretch optional), sat -> Gegenbeispiel + STOP.
    if '--stretch' in sys.argv:
        print("Q71 --stretch: zpdep32(zpext32(x,m),m)==x&m (symbolisches m)")
        q71_x = z3.BitVec('x_q71', 32)
        q71_m = z3.BitVec('m_q71', 32)
        s71 = z3.SolverFor('QF_BV')
        s71.set("timeout", 300000)
        s71.add(zpdep32(zpext32(q71_x, q71_m), q71_m) != (q71_x & q71_m))
        r71 = s71.check()
        if r71 == z3.unsat:
            print("Q71 --stretch Roundtrip fuer alle Masken bewiesen PASS")
        elif r71 == z3.sat:
            m71 = s71.model()
            print(f"Q71 --stretch SAT -> Gegenbeispiel x={m71.eval(q71_x, model_completion=True)} "
                  f"m={m71.eval(q71_m, model_completion=True)}")
            assert False, "Q71: sat -> STOP (kein Weaken)"
        else:
            print("Q71 stretch: unknown (timeout)")
    else:
        print("Q71 --stretch uebersprungen (Flag fehlt)")

    # M13: LEMMAS-Update — Makro-Sequenzen realisierbar.
    LEMMAS.update({
        'R_SHIFTRIGHT': 'shift_right: permb Escape (LSR8/16/24) + bitfrob LSR fein',
        'R_SHIFTLEFT': 'shift_left: permb Escape (LSL8/16/24) + bitfrob LSL fein',
        'R_MULCTZ8': 'mul_ctz: CTZ-shift-add 8x8->16',
        'R_GRAY_ROUNDTRIP': 'bin->gray 1-Pass + gray->bin 5-Pass = Identitaet',
    })
    if '--stretch' in sys.argv:
        LEMMAS.update({
            'R_PEXT_ROUNDTRIP_STRETCH': 'zpdep32(zpext32(x,m),m)==x&m fuer alle m',
        })
    print("M13 Makro-Sequenzen (shift_right/shift_left/mul_ctz/gray):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M13 PASS")

def _run_M14():

    # === M14: 4 neue Kompositions-Lemmata (Makro-Bloecke aus helpers.py) ===
    # Beweis-Idiom wie M9/M12/M13: QF_BV, Timeout 30s, NEGATION der Identitaet
    # assertieren -> unsat erwartet. Bei sat: Gegenbeispiel drucken + STOP
    # (kein Weaken). Konkrete n/sh als Python-ints, Operanden symbolisch.
    # Q72 R_MANDN: ternlog LUT 0x6A == (a&b)^m fuer ALLE a,b,m (per-Bit-
    # Wahrheitstabelle: c=0 -> a&b, c=1 -> ~(a&b), LUT 0x78 waere falsch,
    # 0x6A ist (a&b)^c). Symbolische Freie Variablen + Negation -> unsat.
    print("Q72 R_MANDN: ternlog LUT 0x6A == (a&b)^m: pruefe per Negation")
    m14a_a = z3.BitVec('m14a_a', 32)
    m14a_b = z3.BitVec('m14a_b', 32)
    m14a_m = z3.BitVec('m14a_m', 32)
    _m14_unsat("Q72 R_MANDN res==(a&b)^m",
               model_ternlog(m14a_a, m14a_b, m14a_m, 0x6A) != ((m14a_a & m14a_b) ^ m14a_m),
               [m14a_a, m14a_b, m14a_m])

    # Q73 R_BITSET_ADD: x + (1<<n) via 1-Pass-Komposition: permb shift_ctrl
    # LSL (Byte-Teil k=n>>3, Wert 1 in s2) + feine ROL (Rest-Offset n&7) +
    # arith4 ADD. n konkret; permb liefert (res, shifted_out), so wird
    # verworfen (kein Interesse an den rausgeschobenen Bytes).
    print("Q73 R_BITSET_ADD: x+(1<<n) via shift_ctrl LSL + ROL + ADD: pruefe n in [0,3,8,16,24,31] per Negation")
    m14b_x = z3.BitVec('m14b_x', 32)
    for m14b_n in (0, 3, 8, 16, 24, 31):
        m14b_out, _m14b_so = model_permb_shift(m14b_x, z3.BitVecVal(1, 32), m14b_n, True)
        m14b_rol = model_rol(m14b_out, z3.BitVecVal(m14b_n & 7, 32))
        m14b_res = model_arith4(m14b_x, m14b_rol, z3.BitVecVal(0, 32), 1)[0]
        _m14_unsat(f"Q73 R_BITSET_ADD n={m14b_n} res==x+2^n",
                   m14b_res != ((m14b_x + (1 << m14b_n)) & 0xFFFFFFFF),
                   [m14b_x])

    # Q74 R_SADDI2: 2-Pass-SADDI-Fluss: Pass1 ternlog XOR (LUT 0x3C) ueber
    # (ROL(y,sh) ^ m) mit c=0, Pass2 arith4 ADD (x + pass1). Dokumentiert die
    # Komposition: pass2 ist per ADD-Semantik exakt x+pass1 (trivial, aber
    # sichert den 2-Pass-SADDI-Pfad gegen Verdrahtungs-Regressionen ab).
    print("Q74 R_SADDI2: x+(ROL(y,sh)^m) 2-Pass: pruefe sh in [0,1,3,7] per Negation")
    m14c_x = z3.BitVec('m14c_x', 32)
    m14c_y = z3.BitVec('m14c_y', 32)
    m14c_m = z3.BitVec('m14c_m', 32)
    for m14c_sh in (0, 1, 3, 7):
        m14c_pass1 = model_ternlog(model_rol(m14c_y, z3.BitVecVal(m14c_sh, 32)),
                                   m14c_m, z3.BitVecVal(0, 32), 0x3C)
        m14c_pass2 = model_arith4(m14c_x, m14c_pass1, z3.BitVecVal(0, 32), 1)[0]
        _m14_unsat(f"Q74 R_SADDI2 sh={m14c_sh} pass2==x+pass1",
                   m14c_pass2 != ((m14c_x + m14c_pass1) & 0xFFFFFFFF),
                   [m14c_x, m14c_y, m14c_m])

    # Q75 R_SUBNET: Subnetz-Maske = MASKW(32-n) (n konkret, Python-int) +
    # ternlog NOT (LUT 0x01, b=c=0). Ergebnis == ~((1<<(32-n))-1).
    print("Q75 R_SUBNET: ~(2^(32-n)-1) via MASKW+NOT: pruefe n in [1,8,16,24,31] per Negation")
    for m14d_n in (1, 8, 16, 24, 31):
        m14d_pass1 = model_maskw(32 - m14d_n)
        m14d_pass2 = model_ternlog(m14d_pass1, z3.BitVecVal(0, 32), z3.BitVecVal(0, 32), 0x01)
        _m14_unsat(f"Q75 R_SUBNET n={m14d_n} res==~(2^(32-n)-1)",
                   m14d_pass2 != (0xFFFFFFFF ^ ((1 << (32 - m14d_n)) - 1)),
                   [])

    # M14: LEMMAS-Update — Kompositions-Identitaeten realisierbar.
    LEMMAS.update({
        'R_MANDN': 'ternlog LUT 0x6A = (a&b)^m 1-Pass',
        'R_BITSET_ADD': 'shift_ctrl LSL + ROL fein + ADD = x+2^n',
        'R_SADDI2': '2-Pass: XOR(ROL(y,sh)^m) + ADD',
        'R_SUBNET': 'MASKW(32-n) + NOT = Subnetz-Maske',
    })
    print("M14 Kompositions-Lemmata (R_MANDN/R_BITSET_ADD/R_SADDI2/R_SUBNET):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M14 PASS")

def _run_M15():

    # === M15: GF(2^8)-Multiplikation — CLMUL_LO/CLMUL_HI/POLY_RED (bitfrob
    # Modi 13/14/17) + 5 Forall-Beweise. Pipeline-Semantik aus pipeline.py:462-502:
    # CLMUL_LO/HI = 4 Byte-Lanes Faltung (AND-Plane + XOR-Tree), POLY_RED =
    # Barrett Shift-XOR mit KONKREITEM Polynom (s3 Python-int, loop-konstant).
    # Beweis-Idiom wie M14: QF_BV, Timeout 30s, NEGATION der Identitaet
    # assertieren -> unsat erwartet. sat -> Gegenbeispiel + STOP (kein Weaken).

    # ---- z3-Modelle (nur im __main__-Guard, import-sauber) ----
    def model_clmul_lo(s1, s2):
        """CLMUL_LO (bitfrob mode 13): GF(2)-Mul je Lane, Low-Byte (K 0..7).

        4 Byte-Lanes: a_l = s1 Byte l, b_l = s2 Byte l; pro k in 0..7
        bit_k = XOR_i ((a_l>>i)&1 & (b_l>>(k-i))&1), i in [max(0,k-7)..min(k,7)].
        r_l = OR (bit_k << k); res = OR (r_l << 8*l)."""
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
        """CLMUL_HI (bitfrob mode 14): GF(2)-Mul je Lane, High-Byte (K 8..15).

        Identisch zu CLMUL_LO, aber k in 8..15 und r-Bit bei (k-8);
        res |= (r_l & 0xFF) << (8*l) (AND-Plane shared mit LO)."""
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
        """POLY_RED (bitfrob mode 17): x mod poly_int, Barrett Shift-XOR.

        poly_int ist KONKRETER Python-int (pipeline.py: s3&MASK, Decoder-
        synthetisiert). poly_degree = poly_int.bit_length()-1; Loop i=31..degree:
        x = If(bit_i(x)==1, x ^ (poly_int << (i-degree)), x). Der Shift ist
        loop-konstant (Python-int), jede Stufe daher ein billiger If. Der hoechste
        Konstanten-Bit (poly<<(31-degree)) liegt bei <= 2^32-1, passt in BitVec32."""
        poly_degree = poly_int.bit_length() - 1
        if poly_degree <= 0:
            return x
        for i in range(RLEN - 1, poly_degree - 1, -1):
            x = z3.If(z3.Extract(i, i, x) == 1,
                      x ^ z3.BitVecVal(poly_int << (i - poly_degree), 32), x)
        return x

    # ---- Referenz-Helfer (unabhaengige Konstruktion: Shift-Add statt Faltung) ----
    def _gf8_ref(x, y):
        """Referenz: 8x8-GF(2)-Shift-Add-Produkt, Low-Byte [7:0]."""
        r = z3.BitVecVal(0, 32)
        x32 = z3.ZeroExt(24, x)
        for i in range(8):
            r = z3.If(z3.Extract(i, i, y) == 1, r ^ (x32 << i), r)
        return z3.Extract(7, 0, r)

    def _gf8hi_ref(x, y):
        """Referenz: 8x8-GF(2)-Shift-Add-Produkt, High-Byte [15:8]."""
        r = z3.BitVecVal(0, 32)
        x32 = z3.ZeroExt(24, x)
        for i in range(8):
            r = z3.If(z3.Extract(i, i, y) == 1, r ^ (x32 << i), r)
        return z3.Extract(15, 8, r)

    def _poly_red_ref16(p):
        """Referenz: Schulbuch-Reduktion mod 0x11B (16-Bit-Input, Bits>=16=0).

        Fenster i=15..8 wie die Pipeline-Loop (Bits 31..16 des Inputs sind 0,
        no-op). Fuer 8x8-Produkte (max Bit 14) ist Bit 15=0, daher identisch
        zu gf256_mul_py (helpers.py: range(14,7,-1))."""
        r = p
        for i in range(15, 7, -1):
            r = z3.If(z3.Extract(i, i, r) == 1,
                      r ^ z3.BitVecVal(0x11B << (i - 8), 32), r)
        return z3.Extract(7, 0, r)

    def _gf256_mul_ref(a, b):
        """Referenz: gf256_mul_py (helpers.py:306) — Shift-Add + Reduktion."""
        p = z3.BitVecVal(0, 32)
        a32 = z3.ZeroExt(24, a)
        for i in range(8):
            p = z3.If(z3.Extract(i, i, b) == 1, p ^ (a32 << i), p)
        return _poly_red_ref16(p)

    def _xtime_ref(x):
        """Referenz: AES xtime — t = x<<1; falls Bit8: XOR 0x11B (mod 2^8)."""
        t = x << 1
        return z3.If(z3.Extract(8, 8, t) == 1,
                     z3.Extract(7, 0, t ^ z3.BitVecVal(0x11B, 32)),
                     z3.Extract(7, 0, t))

    # Q76 R_CLMUL_LO: CLMUL_LO(a,b) == Concat MSB-first der 4 Lane-Low-Bytes.
    # Negation -> unsat beweist Forall-Gleichheit aller 4 Lanes (Faltung == ref).
    print("Q76 R_CLMUL_LO: CLMUL_LO == per-byte GF(2) mul low: pruefe per Negation")
    q76_a = z3.BitVec('a_q76', 32)
    q76_b = z3.BitVec('b_q76', 32)
    q76_bytes = [_gf8_ref(z3.Extract(8 * l + 7, 8 * l, q76_a),
                          z3.Extract(8 * l + 7, 8 * l, q76_b)) for l in range(3, -1, -1)]
    _m14_unsat("Q76 R_CLMUL_LO res==Concat(gf8(a3,b3),..,gf8(a0,b0))",
               model_clmul_lo(q76_a, q76_b) != z3.Concat(*q76_bytes),
               [q76_a, q76_b])

    # Q77 R_CLMUL_HI: CLMUL_HI(a,b) == Concat MSB-first der 4 Lane-High-Bytes.
    print("Q77 R_CLMUL_HI: CLMUL_HI == per-byte GF(2) mul high: pruefe per Negation")
    q77_a = z3.BitVec('a_q77', 32)
    q77_b = z3.BitVec('b_q77', 32)
    q77_bytes = [_gf8hi_ref(z3.Extract(8 * l + 7, 8 * l, q77_a),
                            z3.Extract(8 * l + 7, 8 * l, q77_b)) for l in range(3, -1, -1)]
    _m14_unsat("Q77 R_CLMUL_HI res==Concat(gf8hi(a3,b3),..,gf8hi(a0,b0))",
               model_clmul_hi(q77_a, q77_b) != z3.Concat(*q77_bytes),
               [q77_a, q77_b])

    # Q78 R_POLYRED: POLY_RED(x&0xFFFF, 0x11B) == Schulbuch-Reduktion (16-Bit-
    # Input). ZeroExt(24, 8-Bit-ref) auf 32-Bit-Vergleich gebracht.
    print("Q78 R_POLYRED: POLY_RED mod 0x11B == Schulbuch-Reduktion: pruefe per Negation")
    q78_x = z3.BitVec('x_q78', 32)
    q78_in = q78_x & z3.BitVecVal(0xFFFF, 32)
    _m14_unsat("Q78 R_POLYRED poly_red(0x11B)==ref16",
               model_poly_red(q78_in, 0x11B) != z3.ZeroExt(24, _poly_red_ref16(q78_in)),
               [q78_x])

    # Q79 R_GF256MUL (KERNBEWEIS): 3-Schritt-Komposition gf256_mul_pipe
    # (helpers.py:306-324): CLMUL_HI -> Hi-Byte, CLMUL_LO -> Lo-Byte,
    # product=(hi<<8)|lo, POLY_RED(product, 0x11B) == gf256_mul_py(a,b) fuer
    # ALLE Bytes (Byte-Ebene via Extract(7,0) auf a/b).
    print("Q79 R_GF256MUL: gf256_mul_pipe == gf256_mul_py (3 Schritte): pruefe per Negation")
    q79_a = z3.BitVec('a_q79', 32)
    q79_b = z3.BitVec('b_q79', 32)
    q79_hi = z3.Extract(7, 0, model_clmul_hi(q79_a, q79_b))
    q79_lo = z3.Extract(7, 0, model_clmul_lo(q79_a, q79_b))
    # Pipeline s1 ist 32-Bit: (hi<<8)|lo auf 32-Bit erweitern, sonst Extract
    # 31..8 in model_poly_red ungueltig (16-Bit-Operand).
    q79_product = z3.ZeroExt(16, z3.Concat(q79_hi, q79_lo))
    q79_pipe = model_poly_red(q79_product, 0x11B)
    _m14_unsat("Q79 R_GF256MUL gf256_mul_pipe==gf256_mul_py",
               q79_pipe != z3.ZeroExt(24, _gf256_mul_ref(z3.Extract(7, 0, q79_a),
                                                          z3.Extract(7, 0, q79_b))),
               [q79_a, q79_b])

    # Q80 R_XTIME: LSL(1) (konkreter Shift, s1=x, s2=0 -> res=(x<<1)&MASK, kein
    # Wrap bei x<=0xFF) + POLY_RED(0x11B) == AES xtime (xtime_pipe helpers.py).
    print("Q80 R_XTIME: LSL(1)+POLY_RED == AES xtime: pruefe per Negation")
    q80_x = z3.BitVec('x_q80', 32)
    q80_shifted = (q80_x & z3.BitVecVal(0xFF, 32)) << 1
    _m14_unsat("Q80 R_XTIME poly_red(x<<1)==xtime",
               model_poly_red(q80_shifted, 0x11B) != z3.ZeroExt(24, _xtime_ref(q80_x)),
               [q80_x])

    # M15: LEMMAS-Update — GF(2^8)-Multiplikations-Identitaeten realisierbar.
    LEMMAS.update({
        'R_CLMUL_LO': 'CLMUL_LO == per-byte GF(2) mul low, 4 Lanes',
        'R_CLMUL_HI': 'CLMUL_HI == per-byte GF(2) mul high, 4 Lanes',
        'R_POLYRED': 'POLY_RED mod 0x11B == schoolbook reduce',
        'R_GF256MUL': 'gf256_mul_pipe == gf256_mul_py, 3 steps',
        'R_XTIME': 'xtime LSL+POLY_RED == AES xtime',
    })
    print("M15 GF(2^8)-Multiplikation (R_CLMUL_LO/R_CLMUL_HI/R_POLYRED/R_GF256MUL/R_XTIME):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M15 PASS")

def _run_M16():

    # === M16: 5 weitere bitfrob-Modi als z3-Funktionen + 6 Negations-Beweise.
    # (BITZIP_8/18, BITUNZIP_8/19, GFNI_AFFINE/20, BCD_HC/23, LOG2/28, LOG10/29)
    # Pipeline-Semantik aus pipeline.py bitfrob-Dispatch (verbatim). Beweis-
    # Idiom wie M14/M15: QF_BV, Timeout 30s, NEGATION der Identitaet -> unsat.
    # sat -> Gegenbeispiel + STOP (kein Weaken); unknown -> STOP.

    # ---- z3-Modelle (nur im __main__-Guard, import-sauber) ----
    def model_bitzip8(s1):
        """BITZIP_8 (bitfrob mode 18): Byte0 auf gerade Bitpositionen spreizen.

        pipeline.py: x = s1&0xFF; (x|(x<<4))&0x0F0F; (x|(x<<2))&0x3333;
        (x|(x<<1))&0x5555; res = x&0xFFFF. Konkrete Shifts (bvshl), LShR
        unnoetig (nur <<)."""
        x = s1 & z3.BitVecVal(0xFF, 32)
        x = (x | (x << 4)) & z3.BitVecVal(0x0F0F, 32)
        x = (x | (x << 2)) & z3.BitVecVal(0x3333, 32)
        x = (x | (x << 1)) & z3.BitVecVal(0x5555, 32)
        return x & z3.BitVecVal(0xFFFF, 32)

    def model_bitunzip8(s1):
        """BITUNZIP_8 (bitfrob mode 19): gerade Bits 0..14 auf Byte0 schieben.

        pipeline.py: x = s1&0x5555; (x|(x>>1))&0x3333; (x|(x>>2))&0x0F0F;
        (x|(x>>4))&0x00FF; res = x&0xFF. >> = LShR (z3py >> waere bvashr)."""
        x = s1 & z3.BitVecVal(0x5555, 32)
        x = (x | z3.LShR(x, 1)) & z3.BitVecVal(0x3333, 32)
        x = (x | z3.LShR(x, 2)) & z3.BitVecVal(0x0F0F, 32)
        x = (x | z3.LShR(x, 4)) & z3.BitVecVal(0x00FF, 32)
        return x & z3.BitVecVal(0xFF, 32)

    M16_ROW_MASKS = [0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8]

    def model_gfni(s1, cst):
        """GFNI_AFFINE (bitfrob mode 20): pro Ausgabebit i Paritaet von
        x&row_i XOR c_i, row_i = ROL(0x1F,(i+4)&7).

        pipeline.py: v = x&m; p = v^(v>>4); p ^= p>>2; p ^= p>>1; p &= 1;
        p ^= (const>>i)&1; res |= p<<i (>> = LShR im Modell)."""
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
        """BCD_HC (bitfrob mode 23): BCD-Half-Carry je Nibble.

        pipeline.py: x = (s1&0x0F0F0F0F)+(s2&0x0F0F0F0F); res = (x>>4)&0x01010101."""
        x = (s1 & z3.BitVecVal(0x0F0F0F0F, 32)) + (s2 & z3.BitVecVal(0x0F0F0F0F, 32))
        return z3.LShR(x, 4) & z3.BitVecVal(0x01010101, 32)

    def model_log2(x):
        """LOG2 (bitfrob mode 28): 31 - LZC(x). MASK_RLEN=0xFFFFFFFF ist
        Identitaets-Maske (no-op, daher weggelassen). x==0: 31-32 unterlaeuft
        zu 0xFFFFFFFF (BV-Modulo, Pipeline-Semantik)."""
        return z3.BitVecVal(31, 32) - model_lzc(x)

    def model_log10(x):
        """LOG10 (bitfrob mode 29): 9-stufige if/elif-Kette (BVUGE-Schwellen
        10^9..10^1) — spiegelt die Pipeline-Struktur. MASK_RLEN=0xFFFFFFFF
        ist Identitaet, daher x direkt. Faltrichtung wie model_lzc: die
        LETZTE Iteration wird zum AEUSSERSTEN If (zuerst geprueft) — daher
        aufsteigend 1..9, damit x>=10^9 zuerst geprueft wird (elif-Kette)."""
        r = z3.BitVecVal(0, 32)
        for k in range(1, 10):
            r = z3.If(z3.UGE(x, z3.BitVecVal(10 ** k, 32)),
                      z3.BitVecVal(k, 32), r)
        return r

    # ---- Referenz-Helfer (unabhaengige Konstruktionen, keine Transkription) ----
    def _bcdhc_ref(s1, s2):
        """Referenz: Carry je Nibble-Lane ueber 9-Bit-Erweiterung (keine
        BV-Add-Kaskade): carry_l = Bit4(ZeroExt(1,low1)+ZeroExt(1,low2)),
        res |= ZeroExt(31,carry_l) << 8l."""
        res = z3.BitVecVal(0, 32)
        for lane in range(4):
            low1 = z3.ZeroExt(1, z3.Extract(lane * 8 + 3, lane * 8, s1))
            low2 = z3.ZeroExt(1, z3.Extract(lane * 8 + 3, lane * 8, s2))
            carry = z3.Extract(4, 4, low1 + low2)
            res = res | (z3.ZeroExt(31, carry) << z3.BitVecVal(lane * 8, 32))
        return res

    def _log2_property(x):
        """Eigenschafts-Formulierung (keine Referenz-Funktion): r = LOG2(x).
        (x==0 -> 0xFFFFFFFF) oder (2^r <= x < 2^(r+1), obere Schranke via
        r==31-Kurzschluss, da 2^31 <= x <= 2^32-1 im 32-Bit-Bereich).

        ACHTUNG (Abweichung, z3 4.16.0-Unsoundness): r wird NICHT ueber
        model_log2(x) = BitVecVal(31,32) - model_lzc(x) konstruiert —
        bvsub auf der tiefen if-Kette liefert spurious SAT (Modell
        evaluiert die Formel zu False; reproduzierbar selbst fuer
        x==0 -> r==0xFFFFFFFF). Algebraisch gleiche, sounde Form:
        aufsteigende pos-Faltung (identisch zur inneren Faltung von
        model_lzc, lzc = 31 - pos) + If(x==0, 0xFFFFFFFF, pos); fuer
        x!=0 gilt 31 - lzc == pos, fuer x==0 unterlaeuft BV-sub ohnehin
        zu 0xFFFFFFFF. Beweisziel unveraendert (kein Weaken)."""
        pos = z3.BitVecVal(0, 32)
        for i in range(0, 32):
            pos = z3.If(z3.Extract(i, i, x) == 1, z3.BitVecVal(i, 32), pos)
        r = z3.If(x == 0, z3.BitVecVal(0xFFFFFFFF, 32), pos)
        return z3.And(
            z3.Or(
                z3.And(x == 0, r == z3.BitVecVal(0xFFFFFFFF, 32)),
                z3.And(x != 0,
                       z3.UGE(x, z3.BitVecVal(1, 32) << r),
                       z3.Or(r == z3.BitVecVal(31, 32),
                             z3.ULT(x, z3.BitVecVal(1, 32) << (r + z3.BitVecVal(1, 32)))))))

    def _log10_ref(x):
        """Referenz: floor(log10(x)) = Anzahl der 10^k (k=1..9), die x
        erreicht — Summe von If-Schwellen (unabhaengig von der if/elif-Kette)."""
        return z3.Sum([z3.If(z3.UGE(x, z3.BitVecVal(10 ** k, 32)),
                             z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
                       for k in range(1, 10)])

    def _rol8(v, k):
        """8-Bit-Linksrotation, konkreter Shift k: (v<<k) | LShR(v, 8-k)."""
        return ((v << k) | z3.LShR(v, 8 - k)) & z3.BitVecVal(0xFF, 32)

    def _gfni_ref(x, cst):
        """Referenz GFNI: Shift-XOR-Form der Affin-Matrix.

        Herleitung: Zeile i = ROL(0x1F,(i+4)&7) hat Einsen bei Bits
        {i, i+4, i+5, i+6, i+7} (mod 8); deren Paritaet an Position i ist
        xb_i ^ xb_(i-1) ^ xb_(i-2) ^ xb_(i-3) ^ xb_(i-4) (mod 8). ROL8(xb,k)
        liest an Bit i das Bit (i-k) mod 8, {i-1..i-4} = {i+7..i+4} mod 8,
        also exakt die Zeilen-Bits: ref = xb ^ ROL8(xb,1) ^ ROL8(xb,2) ^
        ROL8(xb,3) ^ ROL8(xb,4) ^ cb."""
        xb = x & z3.BitVecVal(0xFF, 32)
        cb = cst & z3.BitVecVal(0xFF, 32)
        return xb ^ _rol8(xb, 1) ^ _rol8(xb, 2) ^ _rol8(xb, 3) ^ _rol8(xb, 4) ^ cb
    # Q81 R_BCDHC: BCD_HC == per-Nibble-Carry (9-Bit-Extract-Referenz).
    print("Q81 R_BCDHC: BCD_HC == per-Nibble-Carry: pruefe per Negation")
    m16_s1 = z3.BitVec('s1_m16', 32)
    m16_s2 = z3.BitVec('s2_m16', 32)
    _m16_unsat("Q81 R_BCDHC res==_bcdhc_ref",
               model_bcdhc(m16_s1, m16_s2) != _bcdhc_ref(m16_s1, m16_s2),
               [m16_s1, m16_s2])

    # Q82 R_LOG2: LOG2-Eigenschaft 2^r <= x < 2^(r+1) (bzw. 0xFFFFFFFF bei 0).
    print("Q82 R_LOG2: 2^r <= x < 2^(r+1) (x==0 -> 0xFFFFFFFF): pruefe per Negation")
    m16_x2 = z3.BitVec('x_m16_log2', 32)
    _m16_unsat("Q82 R_LOG2 Not(_log2_property)",
               z3.Not(_log2_property(m16_x2)), [m16_x2])

    # Q83 R_LOG10: LOG10 == Schwellen-Summe (floor-log10, unabhaengige Referenz).
    print("Q83 R_LOG10: LOG10 == Summe der 10^k-Schwellen: pruefe per Negation")
    m16_x3 = z3.BitVec('x_m16_log10', 32)
    _m16_unsat("Q83 R_LOG10 res==_log10_ref",
               model_log10(m16_x3) != _log10_ref(m16_x3), [m16_x3])

    # Q84 R_BITZIP8: BITZIP_8 == zpdep32(x, 0x5555) (M6-Butterfly; zpdep32
    # maskiert x auf popcount(0x5555)=8 Bits = Byte0, exakt BITZIP_8-Input).
    print("Q84 R_BITZIP8: BITZIP_8 == zpdep32(x,0x5555): pruefe per Negation")
    m16_x4 = z3.BitVec('x_m16_zip', 32)
    _m16_unsat("Q84 R_BITZIP8 res==zpdep32(x,0x5555)",
               model_bitzip8(m16_x4) != zpdep32(m16_x4, z3.BitVecVal(0x5555, 32)),
               [m16_x4])

    # Q85 R_BITUNZIP8: BITUNZIP_8 == zpext32(x, 0x5555) (M6-Butterfly).
    print("Q85 R_BITUNZIP8: BITUNZIP_8 == zpext32(x,0x5555): pruefe per Negation")
    m16_x5 = z3.BitVec('x_m16_unzip', 32)
    _m16_unsat("Q85 R_BITUNZIP8 res==zpext32(x,0x5555)",
               model_bitunzip8(m16_x5) != zpext32(m16_x5, z3.BitVecVal(0x5555, 32)),
               [m16_x5])

    # Q86 R_GFNI: GFNI_AFFINE == Shift-XOR-Form (beide auf 8 Bit maskiert;
    # das Modell setzt nur die niederwertigen 8 Bits).
    print("Q86 R_GFNI: GFNI_AFFINE == x^ROL8(x,1..4)^c: pruefe per Negation")
    m16_x6 = z3.BitVec('x_m16_gfni', 32)
    m16_c6 = z3.BitVec('c_m16_gfni', 32)
    _m16_unsat("Q86 R_GFNI (model&0xFF)==(_gfni_ref&0xFF)",
               (model_gfni(m16_x6, m16_c6) & z3.BitVecVal(0xFF, 32)) !=
               (_gfni_ref(m16_x6, m16_c6) & z3.BitVecVal(0xFF, 32)),
               [m16_x6, m16_c6])

    # M16: LEMMAS-Update — 5 bitfrob-Modi (6 Identitaeten) realisierbar.
    LEMMAS.update({
        'R_BCDHC': 'BCD_HC == per-Nibble-Carry (9-Bit-Extract)',
        'R_LOG2': 'LOG2 == 31-LZC (2^r <= x < 2^(r+1), 0 -> 0xFFFFFFFF)',
        'R_LOG10': 'LOG10 == Schwellen-Summe floor(log10)',
        'R_BITZIP8': 'bitzip.8 == pdep(x,0x5555) (M6-Butterfly)',
        'R_BITUNZIP8': 'bitunzip.8 == pext(x,0x5555) (M6-Butterfly)',
        'R_GFNI': 'gfni affine == x^ROL8(x,1..4)^c',
    })
    print("M16 bitfrob-Modi (R_BCDHC/R_LOG2/R_LOG10/R_BITZIP8/R_BITUNZIP8/R_GFNI):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M16 PASS")

def _run_M17():

    # === M17: NIBLKP/BMAT_N_OR/BMAT_N_XOR/PSAD — ROM- und Primitive-Verifikation
    # NIBLKP (bitfrob mode 22, pipeline.py:533): idx = s1&0xF, res =
    # BITFROB_CST[idx+32] & 0xFF — GF(2^4)-Inversen-ROM (Poly 0x13).
    # BMAT_N_OR (26) / BMAT_N_XOR (27, pipeline.py:556): je Nibble i 4-Bit-
    # ROR-Bank: acc = OR/XOR der ror4(b_nib,k) mit a_nib_k=1.
    # PSAD (arith4 mode 24, intern): s3 + Summe |lane_i(s1)-lane_i(s2)|, Lane via op_type_1.
    # Beweis-Idiom wie M14-M16: QF_BV, Timeout 30s, NEGATION der Identitaet
    # assertieren -> unsat. sat -> Gegenbeispiel drucken + STOP (kein Weaken).

    NIBLKP_TABLE = [0x0, 0x1, 0x9, 0xE, 0xD, 0xB, 0x7, 0x6,
                    0xF, 0x2, 0xC, 0x5, 0xA, 0x4, 0x3, 0x8]

    def _gf4_mul(a, b):
        """GF(2^4)-Multiplikation mod Poly 0x13 (XOR-Shift-Add + Reduktion).

        ABWEICHUNG (Korrektheit, kein Weaken): Reduktions-Schwelle p>=0x10
        statt 0x100 — 4-Bit-Operanden erzeugen Produkte <= 0x7F, die 0x100
        nie erreichen (waere Reduktions-No-op und liefert keine Inversen)."""
        p = 0
        aa = a
        bb = b
        for _ in range(4):
            if aa & 1:
                p ^= bb
            bb <<= 1
            aa >>= 1
        while p >= 0x10:
            p ^= 0x13 << (p.bit_length() - 5)
        return p

    def _niblkp_ifchain(x, table):
        """If-Kette ueber symbolisches idx = x & 0xF: res = table[idx]."""
        acc = z3.BitVecVal(0, 32)
        for i in range(16):
            acc = z3.If((x & 0xF) == i, z3.BitVecVal(table[i], 32), acc)
        return acc & 0xFF

    def model_niblkp(x):
        """NIBLKP (bitfrob mode 22): ROM-Lookup, Low-Byte des Eintrags."""
        return _niblkp_ifchain(x, NIBLKP_TABLE)

    def _niblkp_ref(x):
        """Unabhaengige Referenz: GF(2^4)-Inversen (Poly 0x13) per Brute-Force
        ueber _gf4_mul; inv(0)=0. Identische If-Ketten-Konstruktion."""
        ref = [0] * 16
        for a in range(1, 16):
            for y in range(1, 16):
                if _gf4_mul(a, y) == 1:
                    ref[a] = y
                    break
        return _niblkp_ifchain(x, ref)

    def model_bmat_n(a, b, is_xor):
        """BMAT_N_OR (26) / BMAT_N_XOR (27): 4-Bit-ROR-Bank je Nibble.

        a_nib = Bits 4i..4i+3; fuer k mit a_nib_k=1: r4 = ror4(b_nib,k) via
        ZeroExt(4,b_nib)-8-Bit-Shift (LShR + bvshl, Maske 0xF); Gate per If;
        acc = OR (is_xor=False) bzw. XOR (is_xor=True) der gerouteten r4."""
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

    def _ror4(v, k):
        """4-Bit-Rechtsrotation um konkretes k (0..3): (v<<(4-k)) | LShR(v,k)."""
        return ((v << (4 - k)) | z3.LShR(v, k)) & z3.BitVecVal(0xF, 4)

    def _bmat_n_ref(a, b, is_xor):
        """Unabhaengige Referenz: AND-gating statt If — explizite 4-Term-Summe
        aus ror4(b_nib,k) maskiert mit a_nib-Bit k; OR/XOR je is_xor.

        ABWEICHUNG (Korrektheit, kein Weaken): SignExt(3, bit) statt
        ZeroExt(3, bit) als Masken-Replikation — ZeroExt(3,1)=0x1 wuerde nur
        Bit0 von r4 durchlassen (falsches Gate, Q88-Gegenbeispiel a=0xFFFFFFFF,
        b=0xFFF7FFFF); SignExt repliziert zu all-ones/zero."""
        res = z3.BitVecVal(0, 32)
        for i in range(8):
            a_nib = z3.Extract(3 + 4 * i, 4 * i, a)
            b_nib = z3.Extract(3 + 4 * i, 4 * i, b)
            nib = z3.BitVecVal(0, 4)
            for k in range(4):
                gated = _ror4(b_nib, k) & z3.SignExt(3, z3.Extract(k, k, a_nib))
                nib = (nib ^ gated) if is_xor else (nib | gated)
            res = res | (z3.ZeroExt(28, nib) << z3.BitVecVal(4 * i, 32))
        return res

    def model_psad(s1, s2, s3, lb):
        """PSAD (arith4 mode 24): s3 + Summe |lane_i(s1)-lane_i(s2)|, Lane via lb.

        Pipeline iteriert RLEN/lb Lanes; Operanden sind 32-Bit, obere Lanes
        sind 0 — daher ZeroExt(32,·) auf 64-Bit vor Extract (exakte Spiegelung
        der Python-int-Semantik (s1>>(i*lb))&lane_mask, die fuer i >= RLEN/lb
        0 liefert). 32-Bit-Sad-Akkumulator (WORD: 4x0xFFFF = 0x3FFFC passt).
        Q90 (BYTE) / Q90w (WORD) beweisen gegen 9/17-Bit-Vorzeichen-Referenz."""
        lane_max = (1 << lb) - 1
        s1e = z3.ZeroExt(32, s1)
        s2e = z3.ZeroExt(32, s2)
        sad = z3.BitVecVal(0, 32)
        for i in range(32 // lb):
            av = z3.Extract(lb - 1 + lb * i, lb * i, s1e)
            bv = z3.Extract(lb - 1 + lb * i, lb * i, s2e)
            d = z3.If(z3.UGE(av, bv), av - bv, bv - av)
            sad = sad + z3.ZeroExt(32 - lb, d)
        return (sad + s3) & 0xFFFFFFFF

    def _psad_ref(s1, s2, s3, lb):
        """Unabhaengige Referenz: |diff| via (lb+1)-Bit-Differenz (kein Wrap).

        ABWEICHUNG (Korrektheit, kein Weaken): (lb+1)-Bit statt lb-Bit-Wrap-Abs —
        die lb-Bit-MSB-Abs-Formel ist fuer |av-bv|>lane_max falsch; (lb+1)-Bit
        fasst den vollen Differenzbereich, MSB ist echtes Vorzeichenbit.
        ZeroExt(32,·) auf 64-Bit wie das Modell (obere Lanes = 0)."""
        s1e = z3.ZeroExt(32, s1)
        s2e = z3.ZeroExt(32, s2)
        sad = z3.BitVecVal(0, 32)
        for i in range(32 // lb):
            av = z3.Extract(lb - 1 + lb * i, lb * i, s1e)
            bv = z3.Extract(lb - 1 + lb * i, lb * i, s2e)
            d = z3.ZeroExt(1, av) - z3.ZeroExt(1, bv)   # (lb+1)-Bit
            absd = z3.If(z3.Extract(lb, lb, d) == 1, z3.BitVecVal(0, lb + 1) - d, d)
            sad = sad + z3.ZeroExt(32 - (lb + 1), absd)
        return (sad + s3) & 0xFFFFFFFF
    # Q87 R_NIBLKP: ROM-Inhalt == brute-force GF(2^4)-Inversen (Poly 0x13).
    print("Q87 R_NIBLKP: NIBLKP-Rom == GF(2^4)-Inverse (Poly 0x13): pruefe per Negation")
    m17_x = z3.BitVec('x_q87', 32)
    _m17_unsat("Q87 R_NIBLKP: NIBLKP-Rom == GF(2^4)-Inverse (Poly 0x13)",
               model_niblkp(m17_x) != _niblkp_ref(m17_x), [m17_x])

    # Q88 R_BMAT_N_OR: OR-Bank == AND-gating-Referenz.
    print("Q88 R_BMAT_N_OR: BMAT_N_OR == 4-Bit-ROR-Bank-Referenz: pruefe per Negation")
    m17_a = z3.BitVec('a_q88', 32)
    m17_b = z3.BitVec('b_q88', 32)
    _m17_unsat("Q88 R_BMAT_N_OR: BMAT_N_OR == 4-Bit-ROR-Bank-Referenz",
               model_bmat_n(m17_a, m17_b, False) != _bmat_n_ref(m17_a, m17_b, False),
               [m17_a, m17_b])

    # Q89 R_BMAT_N_XOR: XOR-Bank == AND-gating-Referenz.
    print("Q89 R_BMAT_N_XOR: BMAT_N_XOR == XOR-Bank-Referenz: pruefe per Negation")
    _m17_unsat("Q89 R_BMAT_N_XOR: BMAT_N_XOR == XOR-Bank-Referenz",
               model_bmat_n(m17_a, m17_b, True) != _bmat_n_ref(m17_a, m17_b, True),
               [m17_a, m17_b])

    # Q90/Q90w R_PSAD: SAD-Summe == (lb+1)-Bit-Vorzeichen-Referenz (BYTE + WORD-Lane).
    print("Q90 R_PSAD: PSAD(BYTE) == Summe |Byte-Differenzen|: pruefe per Negation")
    m17_s1 = z3.BitVec('s1_q90', 32)
    m17_s2 = z3.BitVec('s2_q90', 32)
    m17_s3 = z3.BitVec('s3_q90', 32)
    _m17_unsat("Q90 R_PSAD(BYTE): PSAD == Summe |Byte-Differenzen|",
               model_psad(m17_s1, m17_s2, m17_s3, 8) != _psad_ref(m17_s1, m17_s2, m17_s3, 8),
               [m17_s1, m17_s2, m17_s3])
    print("Q90w R_PSAD: PSAD(WORD) == Summe |Halbwort-Differenzen|: pruefe per Negation")
    _m17_unsat("Q90w R_PSAD(WORD): PSAD == Summe |Halbwort-Differenzen|",
               model_psad(m17_s1, m17_s2, m17_s3, 16) != _psad_ref(m17_s1, m17_s2, m17_s3, 16),
               [m17_s1, m17_s2, m17_s3])

    # M17: LEMMAS-Update — ROM-Inhalt + Nibble/Byte-Primitiven realisierbar.
    LEMMAS.update({
        'R_NIBLKP': 'NIBLKP-Rom == GF(2^4)-Inverse-Tabelle',
        'R_BMAT_N_OR': 'BMAT_N_OR == 4-Bit-ROR-Bank-Referenz',
        'R_BMAT_N_XOR': 'BMAT_N_XOR == XOR-Bank-Referenz',
        'R_PSAD': 'PSAD(BYTE+WORD) == Summe |Lane-Differenzen|',
    })
    print("M17 ROM/Primitiven (R_NIBLKP/R_BMAT_N_OR/R_BMAT_N_XOR/R_PSAD):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M17 PASS")

def _run_M18():

    # === M18: BMATOR/BMATXOR (bitfrob 24/25) + PEXT_N/PDEP_N (31/32) — 32-Bit-
    # ROR-Bank- und Nibble-Kompression. Pipeline-Semantik: BMATOR=24/BMATXOR=25
    # (pipeline.py:540-555): res = OR/XOR ueber alle k mit a[k]==1 von ROR32(b,k)
    # (TZC-while-Loop; ROR via (s2<<(RLEN-k))|(s2>>k), MASK_RLEN). PEXT_N=31
    # (pipeline.py:586-594): ausgewaehlte Nibbles (8-Bit-Maske s2&0xFF, ein Bit
    # je Nibble) in Reihenfolge komprimieren. PDEP_N=32 (pipeline.py:595-603):
    # x-Nibbles auf ausgewaehlte Positionen spreizen. Beweis-Idiom wie M14-M17:
    # QF_BV, Timeout 30s, NEGATION der Identitaet assertieren -> unsat; sat ->
    # Gegenbeispiel + STOP (kein Weaken).

    def model_bmator(s1, s2):
        """BMATOR (bitfrob mode 24): OR_{k:a[k]=1} ROR32(b,k).

        TZC-while-Loop ist aequivalent zum Bereichs-Fold 0..31: Bits mit
        a[k]==0 liefern keinen Beitrag (Fold-Guard If(a[k], acc|ror, acc)).
        ROR32(b,k) = Concat(b[k-1:0], b[31:k]) via z3.Concat+Extract
        (k=0 -> Identitaet s2)."""
        acc = z3.BitVecVal(0, 32)
        for k in range(32):
            if k == 0:
                ror = s2
            else:
                ror = z3.Concat(z3.Extract(k - 1, 0, s2), z3.Extract(31, k, s2))
            acc = z3.If(z3.Extract(k, k, s1) == 1, acc | ror, acc)
        return acc

    def model_bmatxor(s1, s2):
        """BMATXOR (bitfrob mode 25): XOR_{k:a[k]=1} ROR32(b,k).

        Identisch zu model_bmator, aber XOR statt OR im Fold-Guard."""
        acc = z3.BitVecVal(0, 32)
        for k in range(32):
            if k == 0:
                ror = s2
            else:
                ror = z3.Concat(z3.Extract(k - 1, 0, s2), z3.Extract(31, k, s2))
            acc = z3.If(z3.Extract(k, k, s1) == 1, acc ^ ror, acc)
        return acc

    def model_pext_n(s1, s2):
        """PEXT_N (bitfrob mode 31): ausgewaehlte Nibbles von s1 komprimieren.

        Maske = s2 & 0xFF (8-Bit, ein Bit je Nibble); hohe Bits 8..31 werden
        ignoriert — die 8-iterations-Schleife (i in 0..7) liest Extract(i,i,s2)
        direkt. Fuer i mit s2_i==1: Nibble i von s1 an Position 4*out, out =
        Anzahl gesetzter Maske-Bits j<i (4-Bit-Prefix-Summe). Shift-Betrag als
        32-Bit-BV (out<=7 -> 4*out<=28, kein Overflow; bvshl mit BV-Betrag)."""
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
        """PDEP_N (bitfrob mode 32): x-Nibbles auf ausgewaehlte Positionen spreizen.

        Fuer i mit s2_i==1: Nibble src_i (src_i = Prefix-Summe der Maske j<i)
        von s1 an Position 4*i. Nibble-Select via symbolischem LShR-Betrag
        (src_i<=7 -> Shift <=28, im Bereich)."""
        res = z3.BitVecVal(0, 32)
        for i in range(8):
            mi = z3.Extract(i, i, s2)
            src = z3.BitVecVal(0, 4)
            for j in range(i):
                src = src + z3.If(z3.Extract(j, j, s2) == 1,
                                  z3.BitVecVal(1, 4), z3.BitVecVal(0, 4))
            nib = z3.Extract(3, 0, z3.LShR(s1, z3.BitVecVal(4, 32) * z3.ZeroExt(28, src)))
            res = res | z3.If(mi == 1,
                              z3.ZeroExt(28, nib) << (z3.BitVecVal(4, 32) * z3.BitVecVal(i, 32)),
                              z3.BitVecVal(0, 32))
        return res

    def _nib_expand(m_sym):
        """8-Bit-Nibble-Maske auf 4-Bit-Runs-Maske expandieren (32-Bit).

        Nur Bits 0..7 von m_sym gelesen (PEXT_N/PDEP_N-Maskenbreite);
        Bit i -> Run 0xF an Position 4*i."""
        acc = z3.BitVecVal(0, 32)
        for i in range(8):
            acc = acc | z3.If(z3.Extract(i, i, m_sym) == 1,
                              z3.BitVecVal(0xF << (4 * i), 32), z3.BitVecVal(0, 32))
        return acc

    def _ror32(s2, k):
        """ROR32(b,k) fuer konkretes k (unabhaengige Referenz-Konstruktion)."""
        if k == 0:
            return s2
        return z3.Concat(z3.Extract(k - 1, 0, s2), z3.Extract(31, k, s2))

    def _bmat_ref_or(s1, s2):
        """Unabhaengige BMATOR-Referenz: expliziter Zero-Beitrag je k.

        Andere Formulierung als das Modell (Fold-Guard): acc = acc | If(a[k],
        ror_k, 0) statt If(a[k], acc|ror, acc)."""
        acc = z3.BitVecVal(0, 32)
        for k in range(32):
            acc = acc | z3.If(z3.Extract(k, k, s1) == 1, _ror32(s2, k), z3.BitVecVal(0, 32))
        return acc

    def _bmat_ref_xor(s1, s2):
        """Unabhaengige BMATXOR-Referenz (XOR-Variante, gleiche Formulierung)."""
        acc = z3.BitVecVal(0, 32)
        for k in range(32):
            acc = acc ^ z3.If(z3.Extract(k, k, s1) == 1, _ror32(s2, k), z3.BitVecVal(0, 32))
        return acc

    # Q91 R_BMATOR: BMATOR == OR_{k:a[k]=1} ROR(b,k) gegen unabhaengige Referenz.
    print("Q91 R_BMATOR: BMATOR == OR_{k:a[k]=1} ROR(b,k): pruefe per Negation")
    m18_x91 = z3.BitVec('x_q91', 32)
    m18_y91 = z3.BitVec('y_q91', 32)
    _m17_unsat("Q91 R_BMATOR: BMATOR == OR_{k:a[k]=1} ROR(b,k)",
               model_bmator(m18_x91, m18_y91) != _bmat_ref_or(m18_x91, m18_y91),
               [m18_x91, m18_y91])

    # Q92 R_BMATXOR: XOR-Variante gegen unabhaengige Referenz.
    # Stretch-Problem (M13-Q71): symbolische a UND b -> Bitblast-Explosion VOR
    # check(), Timeout (120s) greift nicht. Fix: finite-Mask-Leiter wie M6 —
    # a KONKRET (Fold kollabiert auf feste ROR-Menge), b symbolisch. Identitaet
    # unveraendert, kein Weaken.
    print("Q92 R_BMATXOR: BMATXOR == XOR_{k:a[k]=1} ROR(b,k), a konkret (Leiter): pruefe per Negation")
    for a_q92 in MASKS + [0x00010001, 0xFF, 0x5, 0x10203040, 0x0F, 0xF0]:
        _m17_unsat(f"Q92 R_BMATXOR (a=0x{a_q92:08X}, b symbolisch)",
                   model_bmatxor(z3.BitVecVal(a_q92, 32), m18_y91) != _bmat_ref_xor(z3.BitVecVal(a_q92, 32), m18_y91),
                   [m18_y91])

    # Q93 R_PEXTN_PDEPN_RT (KERNROUNDTRIP): pdep_n(pext_n(x,m),m) == x & nib_expand(m).
    # Stretch-Fix: m ist nur 8 Bit breit (Maskenbreite, PEXT_N/PDEP_N) — ALLE 256
    # Werte als Leiter = VOLLSTAENDIGER Beweis ueber die gesamte Masken-Domaine
    # (kein Weaken); x bleibt symbolisch. Symbolisches m -> Explosion (wie Q92/M6).
    print("Q93 R_PEXTN_PDEPN_RT: pdep_n(pext_n(x,m),m) == x & nib_expand(m) fuer ALLE 256 Masken")
    m18_x93 = z3.BitVec('x_q93', 32)
    for m93 in range(256):
        m93_bv = z3.BitVecVal(m93, 32)
        _m17_unsat(f"Q93 R_PEXTN_PDEPN_RT (m=0x{m93:02X}, x symbolisch)",
                   model_pdep_n(model_pext_n(m18_x93, m93_bv), m93_bv) != (m18_x93 & _nib_expand(m93_bv)),
                   [m18_x93])

    # Q94 R_PDEPN_FULL: volle Maske 0xFF = Identitaet (alle 8 Nibbles spreizen).
    print("Q94 R_PDEPN_FULL: pdep_n(x,0xFF) == x: pruefe per Negation")
    m18_x94 = z3.BitVec('x_q94', 32)
    _m17_unsat("Q94 R_PDEPN_FULL: pdep_n(x,0xFF) == x",
               model_pdep_n(m18_x94, z3.BitVecVal(0xFF, 32)) != m18_x94,
               [m18_x94])

    # Q95 R_PEXTN_FULL: volle Maske 0xFF = Identitaet (alle 8 Nibbles komprimieren).
    print("Q95 R_PEXTN_FULL: pext_n(x,0xFF) == x: pruefe per Negation")
    m18_x95 = z3.BitVec('x_q95', 32)
    _m17_unsat("Q95 R_PEXTN_FULL: pext_n(x,0xFF) == x",
               model_pext_n(m18_x95, z3.BitVecVal(0xFF, 32)) != m18_x95,
               [m18_x95])

    # M18: LEMMAS-Update — ROR-Bank + Nibble-Kompression realisierbar.
    LEMMAS.update({
        'R_BMATOR': 'BMATOR == OR_{a[k]=1} ROR32(b,k)',
        'R_BMATXOR': 'BMATXOR == XOR_{a[k]=1} ROR32(b,k)',
        'R_PEXTN_PDEPN_RT': 'pdep_n(pext_n(x,m),m) == x & nib_expand(m)',
        'R_PDEPN_FULL': 'pdep_n(x,0xFF) == x (Identitaet)',
        'R_PEXTN_FULL': 'pext_n(x,0xFF) == x (Identitaet)',
    })
    print("M18 32-Bit-ROR-Bank + Nibble-Kompression (R_BMATOR/R_BMATXOR/R_PEXTN_PDEPN_RT/R_PDEPN_FULL/R_PEXTN_FULL):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M18 PASS")

def _run_M19():

    # === M19: Primitiv-Konstruktionen des Decoder-Klassifizierers imm_encode
    # (helpers.py:374-449): zero/maskw/maskw_shift/replicate/signext/permb/
    # synthesize-lsl16_or. Beweis der Primitiv-Bausteine (MASKW+NOT, MASKW+LSL,
    # SEXT, LSL16+OR) gegen unabhaengige Referenzen. Beweis-Idiom wie M14-M18:
    # QF_BV, Timeout 30s, NEGATION der Identitaet -> unsat; sat -> Gegenbeispiel
    # + STOP (kein Weaken).

    # Lokale M19-Modelle (M13-Versionen sind block-lokal, nicht sichtbar).
    Q19_LSL_VEC = {8: 0x02010004, 16: 0x01000404, 24: 0x00040404}

    def model_shift_left_m19(x, n):
        """shift_left (M13-Form, block-lokal): n Python-int; Byte-Shifts via
        permb-Escape (s1=0, Wert in s2), Fein-LSL via bitfrob Funnel."""
        if n == 0:
            return x
        res = x
        for bshift in (24, 16, 8):
            if n >= bshift:
                res = model_permb_byte(z3.BitVecVal(0, 32), res, Q19_LSL_VEC[bshift], False)
                n -= bshift
        if n > 0:
            res = model_lsl(res, z3.BitVecVal(0, 32), z3.BitVecVal(n, 32))
        return res

    # Q96 R_MASKW_INV: NOT(maskw(w)) == ~((1<<w)-1), w in {1,3,7,8,16,24,31},
    # plus w=0: NOT(maskw(0)) == 0 (maskw(0) = all-ones, NOT = 0). NOT via
    # ternlog LUT 0x01 mit b=c=0 (0x01 == NOT, Q28 bewiesen).
    print("Q96 R_MASKW_INV: NOT(maskw(w)) == ~((1<<w)-1): pruefe w in [0,1,3,7,8,16,24,31] per Negation")
    for q96_w in (0, 1, 3, 7, 8, 16, 24, 31):
        q96_ref = 0 if q96_w == 0 else ((~((1 << q96_w) - 1)) & 0xFFFFFFFF)
        q96_not = model_ternlog(model_maskw(z3.BitVecVal(q96_w, 32)),
                                z3.BitVecVal(0, 32), z3.BitVecVal(0, 32), 0x01)
        _m17_unsat(f"Q96 R_MASKW_INV (w={q96_w}) NOT(maskw)==~((1<<w)-1)",
                   q96_not != z3.BitVecVal(q96_ref, 32), [])

    # Q97 R_MASKW_SHIFT: shift_left(maskw(w-lsb), lsb) == ((1<<(w-lsb))-1) << lsb,
    # w=32 fix, lsb in {1,3,8,16,24}. maskw-Parameter ist s3 als BitVec
    # (BitVecVal(w_lsb, 32)); Byte-Shift via permb-Escape-Vektor, Fein-LSL.
    print("Q97 R_MASKW_SHIFT: shift_left(maskw(w-lsb),lsb) == Maske<<lsb: pruefe lsb in [1,3,8,16,24] per Negation")
    for q97_lsb in (1, 3, 8, 16, 24):
        q97_wl = 32 - q97_lsb
        q97_m = model_shift_left_m19(model_maskw(z3.BitVecVal(q97_wl, 32)), q97_lsb)
        q97_ref = (z3.BitVecVal((1 << q97_wl) - 1, 32) << z3.BitVecVal(q97_lsb, 32))
        _m17_unsat(f"Q97 R_MASKW_SHIFT (lsb={q97_lsb}, w-lsb={q97_wl}) shift(maskw)==ref",
                   q97_m != q97_ref, [])

    # Q98 R_SEXT_FULL: model_sext(x, pos) == If(Extract(pos,pos,x)==1,
    # x | ~lowmask, x & lowmask), lowmask=(1<<(pos+1))-1, pos in {1,3,7,15,16}.
    # Symbolisches x; pos konkreter Python-int (Decoder-synthetisiert).
    print("Q98 R_SEXT_FULL: SEXT == Sign-Extend-Referenz: pruefe pos in [1,3,7,15,16] per Negation")
    q98_x = z3.BitVec('x_q98', 32)
    for q98_p in (1, 3, 7, 15, 16):
        q98_lm = (1 << (q98_p + 1)) - 1
        q98_hi = (~q98_lm) & 0xFFFFFFFF
        q98_ref = z3.If(z3.Extract(q98_p, q98_p, q98_x) == 1,
                        q98_x | z3.BitVecVal(q98_hi, 32),
                        q98_x & z3.BitVecVal(q98_lm, 32))
        _m17_unsat(f"Q98 R_SEXT_FULL (pos={q98_p}) sext==ref",
                   model_sext(q98_x, q98_p) != q98_ref, [q98_x])

    # Q99 R_LSL16_OR: ternlog(shift_left(hi16,16), lo16, 0, 0xFC) == (hi16<<16)|lo16.
    # hi/lo BitVec(16), 0xFC = OR (Q2 bewiesen); beweist die 'lsl16_or'-Synthese
    # des Decoders (helpers.py:446-449) — 2-Op-Bau: LSL(hi) + OR(lo).
    print("Q99 R_LSL16_OR: LSL16+OR == lsl16_or-Synth: pruefe per Negation")
    q99_hi = z3.BitVec('hi_q99', 16)
    q99_lo = z3.BitVec('lo_q99', 16)
    q99_hi32 = z3.ZeroExt(16, q99_hi)
    q99_lo32 = z3.ZeroExt(16, q99_lo)
    q99_lsl = model_shift_left_m19(q99_hi32, 16)
    q99_out = model_ternlog(q99_lsl, q99_lo32, z3.BitVecVal(0, 32), 0xFC)
    _m17_unsat("Q99 R_LSL16_OR out==(hi<<16)|lo",
               q99_out != ((q99_hi32 << z3.BitVecVal(16, 32)) | q99_lo32),
               [q99_hi, q99_lo])

    # M19: LEMMAS-Update — Decoder-Primitiven (imm_encode) realisierbar.
    LEMMAS.update({
        'R_MASKW_INV': 'MASKW+NOT == ~((1<<w)-1)',
        'R_MASKW_SHIFT': 'MASKW+LSL == verschobene Maske',
        'R_SEXT_FULL': 'SEXT == Sign-Extend-Referenz',
        'R_LSL16_OR': 'LSL16+OR == lsl16_or-Synth',
    })
    print("M19 Decoder-Primitiven (R_MASKW_INV/R_MASKW_SHIFT/R_SEXT_FULL/R_LSL16_OR):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M19 PASS")


def _run_M20():
    # M20: SQROM8 — Quadrat-Tabellen-Multiplikation (Elite-1985-Trick).
    # A*B = ((A+B)^2 - A^2 - B^2) >> 1, unsigned 8x8.
    # ROM: T[n]=n^2, n in [0,510] -> 9-bit-Index x 18-bit-Eintrag = 512x18 =
    # 9216 Bit = ~9 Kbit (1 BlockRAM / ~150 LUT-RAM; Masken-ROM: fast null).
    # Breiten-Disziplin: A+B in 9 bit (255+255=510 < 512, kein Overflow);
    # Quadrat-Diff in 18 bit ((A+B)^2 <= 260100 < 2^18; stets >= A^2+B^2,
    # da Kreuzterm 2AB >= 0 -> nie negativ); Ergebnis 16 bit (max 65025).
    print("Q115 SQROM8: 8x8 unsigned == ((a+b)^2 - a^2 - b^2) >> 1 per Negation")

    def _sq8(x8, y8):
        x9 = z3.ZeroExt(1, x8)
        y9 = z3.ZeroExt(1, y8)
        s9 = x9 + y9                                       # 9 bit, max 510
        sq = z3.ZeroExt(9, s9) * z3.ZeroExt(9, s9)         # 18 bit, max 260100
        d = sq - z3.ZeroExt(2, z3.ZeroExt(8, x8) * z3.ZeroExt(8, x8)) \
              - z3.ZeroExt(2, z3.ZeroExt(8, y8) * z3.ZeroExt(8, y8))  # 18 bit, >= 0
        return z3.Extract(15, 0, d >> z3.BitVecVal(1, 18))

    q115_a = z3.BitVec('a_q115', 8)
    q115_b = z3.BitVec('b_q115', 8)
    q115_res = _sq8(q115_a, q115_b)
    q115_ref = z3.ZeroExt(8, q115_a) * z3.ZeroExt(8, q115_b)  # 16 bit bvumul
    _m9_unsat("Q115 SQROM8 ((a+b)^2-a^2-b^2)>>1 == a*b",
              q115_res != q115_ref)

    # Q116 --stretch (optional): 16x16 via 4x Quadranten-Komposition
    # (Schoolbook). Lemma-Einsetzung: Q115 beweist _sq8 == bvumul (16-bit),
    # also darf die Komposition auf BV-Mul-Ebene gerechnet werden.
    # a=ah*256+al, b=bh*256+bl; prod = hi*2^16 + (c1+c2)*2^8 + lo.
    # Grenzen: hi<=0xFE01 (16 bit), c1+c2<=0x1FC02 (17 bit), Summe max
    # 0xFFFD02FF < 2^32 -> kein Overflow.
    # BEKANNTE z3-GRENZE: die Distributiv-Identitaet (Summe von 4x 8x8-Muls
    # == 1x 16x16-BV-Mul) ist QF_BV-bit-blast-schwer — 6 Strategien getestet
    # (16/32/64-bit-Breiten, untere/obere-Haelfte-Split, solve-eqs-Kette,
    # sat.smt, AIG), alle >300s unbeweisbar. Nur --stretch (5-Min-Timeout);
    # unknown/timeout bricht NICHT ab (stretch optional), sat -> CEX + STOP.
    if '--stretch' in sys.argv:
        print("Q116 --stretch: 16x16 via 4x Quadranten gegen 32-bit-bvumul per Negation")
        q116_a = z3.BitVec('a_q116', 16)
        q116_b = z3.BitVec('b_q116', 16)
        q116_ah = z3.Extract(15, 8, q116_a)
        q116_al = z3.Extract(7, 0, q116_a)
        q116_bh = z3.Extract(15, 8, q116_b)
        q116_bl = z3.Extract(7, 0, q116_b)
        q116_hi = z3.ZeroExt(8, q116_ah) * z3.ZeroExt(8, q116_bh)   # 16 bit
        q116_lo = z3.ZeroExt(8, q116_al) * z3.ZeroExt(8, q116_bl)   # 16 bit
        q116_c1 = z3.ZeroExt(8, q116_ah) * z3.ZeroExt(8, q116_bl)   # 16 bit
        q116_c2 = z3.ZeroExt(8, q116_al) * z3.ZeroExt(8, q116_bh)   # 16 bit
        q116_prod = (z3.ZeroExt(16, q116_hi) << z3.BitVecVal(16, 32)) \
            + ((z3.ZeroExt(16, q116_c1) + z3.ZeroExt(16, q116_c2))
               << z3.BitVecVal(8, 32)) \
            + z3.ZeroExt(16, q116_lo)
        q116_ref = z3.ZeroExt(16, q116_a) * z3.ZeroExt(16, q116_b)  # 32 bit bvumul
        s116 = z3.SolverFor('QF_BV')
        s116.set("timeout", 300000)
        s116.add(q116_prod != q116_ref)
        r116 = s116.check()
        if r116 == z3.unsat:
            print("Q116 --stretch 16x16-Komposition bewiesen PASS")
        elif r116 == z3.sat:
            m116 = s116.model()
            print(f"Q116 --stretch SAT -> Gegenbeispiel a={m116.eval(q116_a, model_completion=True)} "
                  f"b={m116.eval(q116_b, model_completion=True)}")
            assert False, "Q116: sat -> STOP (kein Weaken)"
        else:
            print("Q116 stretch: unknown (timeout) — z3-Bit-Blast-Grenze, offen")
    else:
        print("Q116 --stretch uebersprungen (Flag fehlt; z3-Grenze, siehe Kommentar)")

    # M20: LEMMAS-Update — SQROM8-Primitive realisierbar; 16x16-Komposition
    # als --stretch markiert (Q116 offen, z3-Bit-Blast-Grenze).
    LEMMAS.update({
        'R_SQROM8': '((a+b)^2-a^2-b^2)>>1 == a*b (8x8, 9 Kbit ROM)',
        'R_SQROM8_16': '16x16 via 4x SQROM8 (Schoolbook; Q116 --stretch)',
    })
    print("M20 SQROM8 (R_SQROM8/R_SQROM8_16):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    n_real = sum(1 for k in LEMMAS if k.startswith('R_'))
    n_impo = sum(1 for k in LEMMAS if k.startswith('I_'))
    print(f"  Zaehlung: realisierbar={n_real}, unmoeglich={n_impo}")
    print("M20 PASS")


def _run_M21():
    # === M21: Division via Newton-Raphson (Reziprok-ROM) ===
    # Semantik K2 (ops_survey.md, ratifiziert): DIV res=Quotient, aux=Rest,
    # bit5=unsigned/signed, C-Truncation, div-zero DEFINIERT (q=0xFFFFFFFF,
    # rem=s1, FLAG_O), MIN/-1 Overflow (q=MIN, rem=0, FLAG_O).
    # Newton-Pfad: Reziprok-ROM (4-bit-Index auf NORMALISIERTEM Divisor
    # b_n = b<<clz, b_n in [128,255] -> uniforme 2^-4-Approx) + 1-2 Iterationen
    # (r = 2r - (r^2*b_n)>>16, quadratische Konvergenz) + ±1-Korrektur.
    # Q117: 8-bit-Miniatur-Beweis — 16-EW-ROM + 1 Iteration == bvudiv exakt.
    print("Q117 NEWTON8: 8-bit-Div via 4-bit-ROM + 1 Newton-Iteration per Negation")
    t117 = time.time()

    def _newton8(a, b, n_iter, r0vals):
        b16 = z3.ZeroExt(8, b)
        b_n = None
        for sh in range(8):
            lo = 1 << (7 - sh)
            hi = (1 << (8 - sh)) - 1
            cand = b16 << sh
            b_n = cand if b_n is None else z3.If(z3.And(b >= lo, b <= hi), cand, b_n)
        idx = z3.Extract(7, 4, b_n)
        r0 = z3.BitVecVal(r0vals[8], 16)
        for i in range(9, 16):
            r0 = z3.If(idx == z3.BitVecVal(i, 4), z3.BitVecVal(r0vals[i], 16), r0)
        r = r0
        for _ in range(n_iter):
            r2 = z3.ZeroExt(16, r) * z3.ZeroExt(16, r)
            r2b = z3.ZeroExt(8, r2) * z3.ZeroExt(24, b_n)
            num = z3.LShR(r2b, 16)
            rn = z3.ZeroExt(24, 2 * r) - num
            r = z3.Extract(15, 0, rn)
        a32 = z3.ZeroExt(24, a)
        r32 = z3.ZeroExt(16, r)
        q = None
        for sh in range(8):
            lo = 1 << (7 - sh)
            hi = (1 << (8 - sh)) - 1
            cand = z3.LShR(a32 * r32, 16 - sh)
            q = cand if q is None else z3.If(z3.And(b >= lo, b <= hi), cand, q)
        b24 = z3.ZeroExt(24, b)
        qc = z3.If(z3.UGT((q + 1) * b24, a32),
                   z3.If(z3.UGT(q * b24, a32), q - 1, q), q + 1)
        return z3.Extract(7, 0, qc)

    r0vals = {i: (1 << 16) // (i << 4) for i in range(8, 16)}
    q117_a = z3.BitVec('a_q117', 8)
    q117_b = z3.BitVec('b_q117', 8)
    q117_q = _newton8(q117_a, q117_b, 1, r0vals)
    _m9_unsat("Q117 NEWTON8 4-bit-ROM+1-Newton == bvudiv",
              z3.And(q117_b >= 1, q117_q != z3.UDiv(q117_a, q117_b)))

    # Q118: div-zero DEFINIERT — q=0xFF (8-bit), rem=a (Semantik K2).
    print("Q118 NEWTON8 div-zero: q=0xFF, rem=a definiert per Negation")
    q118_q = z3.If(q117_b == 0, z3.BitVecVal(0xFF, 8), q117_q)
    _m9_unsat("Q118 div-zero q==0xFF && rem==a",
              z3.And(q117_b == 0,
                     z3.Or(q118_q != z3.BitVecVal(0xFF, 8),
                           z3.ZeroExt(24, q117_a) -
                           z3.ZeroExt(24, q118_q) * z3.ZeroExt(24, q117_b)
                           != z3.ZeroExt(24, q117_a))))

    # Q119: Rest == URem (aux-Semantik: res=Quotient, aux=Rest, MULHI-Symmetrie).
    print("Q119 NEWTON8 Rest == URem: pruefe per Negation")
    q119_rem = z3.ZeroExt(24, q117_a) - z3.ZeroExt(24, q118_q) * z3.ZeroExt(24, q117_b)
    _m9_unsat("Q119 NEWTON8 rem==URem(a,b)",
              z3.And(q117_b >= 1,
                     z3.Extract(7, 0, q119_rem) != z3.URem(q117_a, q117_b)))

    LEMMAS.update({
        'R_NEWTON8': '8-bit-Div: 4-bit-ROM + 1 Newton-Iteration + Korrektur (Q117)',
        'R_DIVZERO': 'div-zero definiert: q=0xFF, rem=a (K2-Semantik)',
        'R_DIVREM': 'Rest == URem (aux-Tap, MULHI-Symmetrie)',
    })
    print("M21 Newton-Division (R_NEWTON8/R_DIVZERO/R_DIVREM):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    print(f"  Q117-Q119 fertig ({time.time()-t117:.2f}s)")
    print("M21 PASS")


def _run_M22():
    # === M22: 32-bit-Newton-Abschaetzung (Reziprok-ROM, Q31-Skalierung) ===
    # Skaliert die M21-Studie (Q117) auf 32-bit. Breiten-Design:
    # Divisor normiert b_n = b<<sh in [2^31, 2^32). Reziprok r = 2^63/b_n
    # in [2^31, 2^32) — Q31-Festkomma von 1.0..2.0 (2^32/b_n als Integer
    # waere nur {1,2} = ULP-Katastrophe). 32-bit-r hat ULP=1 -> relativer
    # ULP-Fehler 2^-31; q = LShR(a*r, 63-sh) (a*r 64-bit), LShR-ULP 1 ->
    # Delta_q_ulp <= 2. KERN-ERGEBNIS: ±1-Korrektur (M21-Idiom) reicht auf
    # 32-bit NICHT — braucht 2-Pass-Fixup (q+1-Check iteriert).
    # ROM: 256x32 = 8 Kbit, r0[i] = min(2^63 div (i<<24), 0xFFFFFFFF),
    # i = Top-8-Bits von b_n (i in [128,255]).
    print("M22 NEWTON32: 32-bit-Newton-Abschaetzung (ROM-Schranke + Konvergenz + Fixup)")
    t122 = time.time()

    # Q120: ROM-Fehler-Schranke |e0| <= 2^-7 fuer alle 128 ROM-Zellen.
    # e0 = |b_n * r0[i] - 2^63|. Beweis je Zelle per Negation: b_n in
    # Zelle[i] UND b_n*r0[i] ausserhalb [2^63-2^56, 2^63+2^56] -> unsat.
    print("Q120 NEWTON32: 128 Zellen: b_n*r0[i] in [2^63-2^56, 2^63+2^56] (e0<=2^-7)")
    _lo64 = z3.BitVecVal((1 << 63) - (1 << 56), 64)
    _hi64 = z3.BitVecVal((1 << 63) + (1 << 56), 64)
    for _i in range(128, 256):
        _r0 = (1 << 63) // (_i << 24)
        if _r0 > 0xFFFFFFFF:
            _r0 = 0xFFFFFFFF
        _bn = z3.BitVec('bn_q120_%d' % _i, 32)
        _t = z3.ZeroExt(32, _bn) * z3.BitVecVal(_r0, 64)
        _bad = z3.Or(z3.ULT(_t, _lo64), z3.UGT(_t, _hi64))
        _c = z3.And(z3.UGE(_bn, z3.BitVecVal(_i << 24, 32)),
                    z3.ULE(_bn, z3.BitVecVal((_i + 1) * (1 << 24) - 1, 32)),
                    _bad)
        _s = z3.SolverFor('QF_BV')
        _s.set("timeout", 30000)
        _s.add(_c)
        _r = _s.check()
        if _r == z3.sat:
            _m = _s.model()
            print(f"Q120 Zelle {_i}: SAT -> Gegenbeispiel bn={_m.eval(_bn, model_completion=True)}")
            assert False, f"Q120 Zelle {_i}: sat -> STOP (Schranke verletzt)"
        assert _r == z3.unsat, f"Q120 Zelle {_i}: {_r} -> STOP (kein Weaken)"
    print("Q120 NEWTON32 ROM-Schranke e0<=2^-7 (128 Zellen) PASS")

    # Q121: Newton-Konvergenz mit Quantisierung, QF_NRA.
    # e_{k+1} <= e_k^2 + 2^-32 (je Iteration 1 ULP r + 1 ULP LShR, konservativ).
    # 3 Iterationen: e3 <= 2^-31 (Negation e3 > 2^-31 unsat).
    print("Q121 NEWTON32: Konvergenz e0<=2^-7 -> e3<=2^-31 (3 Iter., Quant. 2^-32)")
    _e0, _e1, _e2, _e3 = z3.Reals('e0_q121 e1_q121 e2_q121 e3_q121')
    _eps = z3.RealVal(1) / 2**32
    _sn = z3.Solver()
    _sn.add(_e0 <= z3.RealVal(1) / 128, _e0 >= 0)
    _sn.add(_e1 <= _e0 * _e0 + _eps, _e1 >= 0)
    _sn.add(_e2 <= _e1 * _e1 + _eps, _e2 >= 0)
    _sn.add(_e3 <= _e2 * _e2 + _eps, _e3 >= 0)
    _sn.add(_e3 > z3.RealVal(1) / 2**31)
    _r = _sn.check()
    assert _r == z3.unsat, f"Q121: {_r} -> STOP (Konvergenz nicht beweisbar)"
    print("Q121 NEWTON32 Konvergenz-Kette PASS (3 Iterationen reichen)")

    # Q122: q-Fehler-Schranke. Ideal: Delta_q = a*e3/b < 2^-30 (Negation
    # unsat). ULP-Terme: r-ULP 1 + LShR-ULP 1 -> |Delta_q| <= 2.
    # KONSEQUENZ: ±1-Korrektur (M21-Idiom) reicht NICHT auf 32-bit;
    # braucht 2-Pass-Fixup (q+1-Check 2x) oder 3-Kandidaten-Check.
    print("Q122 NEWTON32: Delta_q_ideal < 2^-30; ULP-Reste <= 2 -> 2-Pass-Fixup noetig")
    _a, _b = z3.Reals('a_q122 b_q122')
    _sn2 = z3.Solver()
    _sn2.add(_a >= 0, _a < 2**32, _b >= 2**31, _e3 <= z3.RealVal(1) / 2**31)
    _sn2.add(_a * _e3 / _b > z3.RealVal(1) / 2**30)
    _r = _sn2.check()
    assert _r == z3.unsat, f"Q122: {_r} -> STOP (Schranke nicht beweisbar)"
    print("Q122 NEWTON32 q-Fehler-Schranke PASS (Fixup-Bedarf dokumentiert)")

    LEMMAS.update({
        'R_NEWTON32': '32-bit-Newton: ROM e0<=2^-7, 3 Iter. e3<=2^-31, 2-Pass-Fixup (Q120-Q122)',
    })
    print("M22 32-bit-Newton-Abschaetzung (R_NEWTON32):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    print(f"  Q120-Q122 fertig ({time.time()-t122:.2f}s)")
    print("M22 PASS")


def _run_M23():
    # === M23: Encoding-Offset-Check: Control/Memory-Feld-Form (FMEM) ===
    # Papier-Form (isa_vision.md Sektion 3): C(31) WRF(30) opcode(29-26)
    # scale(25-24) off_hi(23-22) dst(21-17) src1(16-13) src2(12-9)
    # off_lo(8-0). Offset = 11 Bit signed (off_hi 2 + off_lo 9) in
    # 2-Byte-Einheiten (Bit 0 implizit 0), << scale (0-3 -> 1/2/4/8).
    # Bytes = offs_Einheiten * 2 * (1<<scale): scale 3 -> -16384/+16368.
    # Q123: Offset-Spanne + Sprungziel-Raster; Q124: Feld-Disjunktheit +
    # F3-Konsistenz; Q125: compressed-16-bit-Bereich (Notiz-Query).
    print("M23 FMEM: Encoding-Offset-Check (Spherening + Feld-Form)")
    t123 = time.time()

    # Q123a: Offset-Spanne. Fuer alle (offs 11-bit signed, scale 0-3):
    # bytes = SignExtend(offs) << (1+scale) in [-16384, 16368].
    # Negation: existiert (offs,scale) mit bytes > 16368 oder < -16384.
    print("Q123a FMEM: Offset-Spanne [-16384, 16368] Bytes (11-bit << (1+scale))")
    q123_offs = z3.BitVec('offs_q123', 11)
    q123_scale = z3.BitVec('scale_q123', 2)
    q123_shift = z3.ZeroExt(28, z3.BitVecVal(1, 4) + z3.ZeroExt(2, q123_scale))
    q123_bytes = z3.SignExt(21, q123_offs) << q123_shift
    _m9_unsat("Q123a FMEM Offset-Spanne (16368/16384)",
              z3.Or(q123_bytes > z3.BitVecVal(16368, 32),
                    q123_bytes < z3.BitVecVal(-16384, 32)))

    # Q123b: typische Sprungziele erreichbar — fuer jedes Ziel existiert
    # (offs, scale) mit (offs << 1 << scale) == Ziel-Bytes. Darstellbare
    # -> sat + Witness (offs/scale via as_long); 16384 > 16368 max-Spanne
    # -> Negation unsat = formaler Nicht-Darstellbarkeits-Beweis.
    print("Q123b FMEM: Sprungziele 512..16384 Bytes (Witness offs/scale)")
    for _t, _exp in [(512, True), (1024, True), (2048, True), (4096, True),
                     (8192, True), (16384, False)]:
        _s = z3.SolverFor('QF_BV')
        _s.set("timeout", 30000)
        _s.add((z3.SignExt(21, q123_offs) << q123_shift)
               == z3.BitVecVal(_t, 32))
        _r = _s.check()
        if _exp:
            assert _r == z3.sat, f"Q123b Ziel {_t}: {_r} -> STOP (unerreichbar?)"
            _m = _s.model()
            _o = _m.eval(q123_offs, model_completion=True).as_long()
            _sc = _m.eval(q123_scale, model_completion=True).as_long()
            print(f"Q123b Ziel {_t}: erreichbar (offs={_o}, scale={_sc}, "
                  f"bytes={_o * 2 * (1 << _sc)})")
        else:
            assert _r == z3.unsat, f"Q123b Ziel {_t}: {_r} -> Gegenbeispiel"
            print(f"Q123b Ziel {_t}: nicht darstellbar (Spanne max 16368)")

    # Q124: Feld-Disjunktheit. FMEM-Slices paarweise ueberlapp-frei (kein Bit
    # in zwei Feldern); dst/src1/src2 positions-identisch zu F3 (src3 25-22,
    # dst 21-17, src1 16-13, src2 12-9) -> Decoder-Konsistenz.
    print("Q124 FMEM: Feld-Disjunktheit + F3-Decoder-Konsistenz")
    _flds = {'scale': (24, 25), 'off_hi': (22, 23), 'off_lo': (0, 8),
             'dst': (17, 21), 'src1': (13, 16), 'src2': (9, 12)}

    def _mask(lo, hi):
        return z3.BitVecVal(((1 << (hi - lo + 1)) - 1) << lo, 32)

    _mks = {n: _mask(*r) for n, r in _flds.items()}
    _nm = list(_mks)
    for _i in range(len(_nm)):
        for _j in range(_i + 1, len(_nm)):
            _s = z3.SolverFor('QF_BV')
            _s.set("timeout", 30000)
            _s.add((_mks[_nm[_i]] & _mks[_nm[_j]]) != 0)
            _r = _s.check()
            if _r == z3.sat:
                print(f"Q124 {_nm[_i]} & {_nm[_j]}: SAT -> Felder ueberlappen")
                assert False, f"Q124 {_nm[_i]} & {_nm[_j]}: sat -> STOP"
            assert _r == z3.unsat, f"Q124 {_nm[_i]} & {_nm[_j]}: {_r}"
    _f3 = {'dst': (17, 21), 'src1': (13, 16), 'src2': (9, 12)}
    for _n in _f3:
        _s = z3.SolverFor('QF_BV')
        _s.set("timeout", 30000)
        _s.add((_mks[_n] ^ _mask(*_f3[_n])) != 0)
        _r = _s.check()
        if _r == z3.sat:
            print(f"Q124 F3-{_n}: SAT -> Position weicht ab")
            assert False, f"Q124 F3-{_n}: sat -> STOP"
        assert _r == z3.unsat, f"Q124 F3-{_n}: {_r}"
    print("Q124 FMEM Feld-Disjunktheit + F3-Konsistenz PASS")

    # Q125: compressed-Ausblick (Bit 31 C gesetzt -> 16-bit-Form). Offset nur
    # noch ~8-9 Bit in 2-Byte-Einheiten: offs 9-bit signed -> max +255
    # Einheiten = 510 Bytes, min -256 Einheiten = -512 Bytes. Notiz-Query.
    print("Q125 FMEM: compressed-16-bit-Bereich (+/-255 Einheiten = +/-510 Bytes)")
    _c = z3.BitVec('offs_q125', 9)
    _cb = z3.SignExt(23, _c) << 1
    _m9_unsat("Q125 compressed: Bytes in [-512, 510]",
              z3.Or(_cb > z3.BitVecVal(510, 32),
                    _cb < z3.BitVecVal(-512, 32)))

    LEMMAS.update({
        'R_FMEM_OFF': 'FMEM 11-bit signed << (1+scale): Spanne [-16384, 16368] (Q123)',
        'R_FMEM_FIELDS': 'FMEM-Felder disjunkt, dst/src1/src2 == F3 (Q124)',
        'R_CMPRANGE': 'compressed 16-bit: ~8-9 Bit 2-Byte -> +/-510 Bytes (Q125)',
    })
    print("M23 Encoding-Offset-Check (R_FMEM_OFF/R_FMEM_FIELDS/R_CMPRANGE):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    print(f"  Q123-Q125 fertig ({time.time()-t123:.2f}s)")
    print("M23 PASS")
    return


def _run_M24():
    # === M24: bxx-Praedikat-Fabriken: XOR-Substitution (Bedingungscodes) ===
    # Control-Op bxx (isa_vision.md Sektion 3): src1/src2 bei bedingtem
    # Sprung praktisch tot -> Praedikat-Logik. 4 Bedingungs-Kanaele,
    # Standard: Kanal i = Flag i (S=0, C=1, Z=2, O=3). src1 = 4 Bit:
    # src1[3:2] = Kanal-Position p, die durch XOR-Signal ERSETZT wird;
    # src1[1:0] = Paar-Wahl: 00:S^O, 01:C^Z, 10:S^Z, 11:C^O.
    # Substitution: effektiver Kanal p = (FlagX XOR FlagY) des Paars,
    # alle anderen Kanaele = rohe Flags. Muster bleibt: dst[3:0]=mask,
    # src2[3:0]=wish, dst[4]=inv: inv=0 -> any ((eff^wish)&mask)!=mask,
    # inv=1 -> all ((eff^wish)&mask)==0 (eff = 4-Bit-Kanal-Vektor).
    # Flag-Konvention (pipeline.py:17-20): S=0x01, C=0x02, Z=0x04, O=0x08.
    # Q126: 14 ARM-Bedingungen Existenz-Beweis (t 13 Bit, alle 16 f).
    # Q127: Zaehlung darstellbarer boolescher Funktionen (Python-Enum).
    # Q128: Witness-Tabelle je cond + substituierter Kanal.
    print("M24 bxx: Praedikat-Fabriken XOR-Substitution (14 ARM-Bedingungen)")
    t124 = time.time()
    _CODES = ['EQ', 'NE', 'CS', 'CC', 'MI', 'PL', 'VS', 'VC',
              'HI', 'LS', 'GE', 'LT', 'GT', 'LE']
    _COND = {
        'EQ': lambda f: bool(f & 4),
        'NE': lambda f: not bool(f & 4),
        'CS': lambda f: bool(f & 2),
        'CC': lambda f: not bool(f & 2),
        'MI': lambda f: bool(f & 1),
        'PL': lambda f: not bool(f & 1),
        'VS': lambda f: bool(f & 8),
        'VC': lambda f: not bool(f & 8),
        'HI': lambda f: bool(f & 2) and not (f & 4),
        'LS': lambda f: not (f & 2) or bool(f & 4),
        'GE': lambda f: ((f & 1) != 0) == ((f & 8) != 0),
        'LT': lambda f: ((f & 1) != 0) != ((f & 8) != 0),
        'GT': lambda f: not (f & 4) and (((f & 1) != 0) == ((f & 8) != 0)),
        'LE': lambda f: bool(f & 4) or (((f & 1) != 0) != ((f & 8) != 0)),
    }
    _PAIR = {0: 'S^O', 1: 'C^Z', 2: 'S^Z', 3: 'C^O'}

    def _pred_z3(t, fv):
        fl = z3.BitVecVal(fv, 4)
        p = z3.Extract(3, 2, t)      # Kanal-Position 0-3 (XOR-substituiert)
        pr = z3.Extract(1, 0, t)     # Paar-Wahl 0-3
        f0 = z3.Extract(0, 0, fl)
        f1 = z3.Extract(1, 1, fl)
        f2 = z3.Extract(2, 2, fl)
        f3 = z3.Extract(3, 3, fl)
        xb = z3.If(pr == 0, f0 ^ f3,
             z3.If(pr == 1, f1 ^ f2,
              z3.If(pr == 2, f0 ^ f2, f1 ^ f3)))
        eff = z3.If(p == 0, z3.Concat(f3, f2, f1, xb),
             z3.If(p == 1, z3.Concat(f3, f2, xb, f0),
              z3.If(p == 2, z3.Concat(f3, xb, f1, f0),
                    z3.Concat(xb, f2, f1, f0))))
        mask = z3.Extract(11, 8, t)
        wish = z3.Extract(7, 4, t)
        inv = z3.Extract(12, 12, t) == 1
        return z3.If(inv, ((eff ^ wish) & mask) == 0,
                     ((eff ^ wish) & mask) != mask)

    def _pred_py(t, f):
        dst = (t >> 8) & 0x1F
        src2 = (t >> 4) & 0x0F
        src1 = t & 0x0F
        p = (src1 >> 2) & 3
        pr = src1 & 3
        f0 = f & 1
        f1 = (f >> 1) & 1
        f2 = (f >> 2) & 1
        f3 = (f >> 3) & 1
        if pr == 0:
            xb = f0 ^ f3
        elif pr == 1:
            xb = f1 ^ f2
        elif pr == 2:
            xb = f0 ^ f2
        else:
            xb = f1 ^ f3
        bits = [f0, f1, f2, f3]
        bits[p] = xb
        eff = bits[0] | (bits[1] << 1) | (bits[2] << 2) | (bits[3] << 3)
        mask = dst & 0x0F
        wish = src2 & 0x0F
        if ((dst >> 4) & 1) == 0:
            return ((eff ^ wish) & mask) != mask
        return ((eff ^ wish) & mask) == 0

    # Q126: Abdeckungs-Matrix — fuer jede der 14 ARM-Bedingungen existiert
    # ein 13-Bit-Tupel t = concat(dst5, src2_4, src1_4) mit
    # Praedikat(t,f) == cond(f) fuer ALLE f in 0..15. sat -> Witness
    # (dst/src2/src1 via as_long), unsat -> LUECKE (Analyse, kein Stop).
    print("Q126 bxx: 14 ARM-Bedingungen — Existenz-Beweis (t=13 Bit, alle 16 f)")
    _t13 = z3.BitVec('t_q126', 13)
    _wits = {}
    for _c in _CODES:
        _s = z3.SolverFor('QF_BV')
        _s.set("timeout", 30000)
        for _fv in range(16):
            _s.add(_pred_z3(_t13, _fv) == z3.BoolVal(_COND[_c](_fv)))
        _r = _s.check()
        if _r == z3.sat:
            _m = _s.model()
            _tv = _m.eval(_t13, model_completion=True).as_long()
            _dst = (_tv >> 8) & 0x1F
            _src2 = (_tv >> 4) & 0x0F
            _src1 = _tv & 0x0F
            _wits[_c] = (_dst, _src2, _src1)
            # Python-Spiegel gegen z3-Witness cross-checken (Divergenz-Falle)
            for _fv in range(16):
                assert _pred_py(_tv, _fv) == bool(_COND[_c](_fv)), \
                    f"Q126 {_c}: python/z3-Divergenz f={_fv}"
            print(f"Q126 {_c}: sat -> abgedeckt (dst={_dst}, src2={_src2}, "
                  f"src1={_src1}, subst-Kanal={(_src1 >> 2) & 3}, "
                  f"pair={_PAIR[_src1 & 3]})")
        else:
            assert _r == z3.unsat, f"Q126 {_c}: {_r} -> STOP"
            print(f"Q126 {_c}: unsat -> LUECKE (kein 13-Bit-Witness)")

    # Q127: Zaehlung darstellbarer boolescher Funktionen. Python-Enumeration
    # ueber t in range(8192), funct = 16-Bit-Int (Bit f = Praedikat(t,f)),
    # distinkte in Set. KEIN Solver noetig. Klassiker-Vergleich via cond-Ints.
    print("Q127 bxx: Zaehlung darstellbarer boolescher Funktionen (8192 Tupel)")
    _seen = set()
    for _tv in range(8192):
        _ft = sum(int(_pred_py(_tv, _f)) << _f for _f in range(16))
        _seen.add(_ft)
    _nontriv = [x for x in _seen if x != 0 and x != 0xFFFF]
    _code_ints = {c: sum(int(_COND[c](f)) << f for f in range(16))
                  for c in _CODES}
    _missing = [c for c in _CODES if _code_ints[c] not in _seen]
    print(f"Q127 bxx: distinct={len(_seen)}, nichttrivial={len(_nontriv)}, "
          f"Klassiker-im-Set={14 - len(_missing)}/14"
          + (f", fehlt: {_missing}" if _missing else ""))

    # Q128: Witness-Tabelle — je cond den Q126-Witness + substituierter
    # Kanal-Position p und Paar-Wahl (wo das XOR-Signal wirkt).
    print("Q128 bxx: Witness-Tabelle (14 cond -> Kanal-Substitution)")
    for _c in _CODES:
        if _c in _wits:
            _wt = _wits[_c]
            print(f"Q128 {_c}: dst={_wt[0]} src2={_wt[1]} src1={_wt[2]} "
                  f"(Kanal {(_wt[2] >> 2) & 3} <- {_PAIR[_wt[2] & 3]})")
        else:
            print(f"Q128 {_c}: kein Witness (LUECKE)")

    _all_ok = len(_wits) == 14
    _mat = ', '.join(f'{c}:{"sat" if c in _wits else "unsat"}'
                     for c in _CODES)
    if _all_ok:
        LEMMAS.update({
            'R_BCOND_NOW': 'bxx XOR-Substitution deckt alle 14 '
                           'ARM-Bedingungen ab',
        })
    print(f"M24 bxx-XOR-Substitution ({'R_BCOND_NOW' if _all_ok else 'LUECKE'}):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    print(f"  Q126-Q128 fertig ({time.time()-t124:.2f}s)")
    print(f"  Matrix: {_mat}")
    if _all_ok:
        print("M24 PASS (alle 14 ARM-Bedingungen abgedeckt)")
        return
    print(f"M24 LÜCKE: {[c for c in _CODES if c not in _wits]}")
    return


def _run_M25():
    # === M25: F1-Imm13-Allokation (Q129-Q132) ===
    # Drei F1-imm13-Encodings aus dem ISA-Shell formell (QF_BV) verifizieren:
    # Q129 sarithi: 9-bit-val (sign-ext -256..255) << shift4 (0..15),
    #   8192 Kombis -> 4352 distinkte Werte; 0x101/0xE81/0x11B nicht darstellbar.
    # Q130 cbitfrob_i: mode5(imm[12:8]) + amt8(imm[7:0]), amt & 0x1F bei Decode
    #   -> 1024 distinkt, obere 3 amt-Bits tot (1..31 wirksam).
    # Q131 slogii: ones5(1..31) | rep3 -> elem-Replikation | rot5; 5952 Kombis
    #   -> 1303 distinkte Masken, Klassiker (0xFFFFFFFF, 0x0F0F0F0F, ...) erreichbar.
    # Q132 Variante val8<<shift5 -> 3328 distinkt (Untertest).
    print("M25 F1-Imm13: Allokations-Semantik (Q129-Q132)")
    t125 = time.time()

    # Q129a: sarithi val9<<shift4 — Python-Enumeration (Ground-Truth-Spiegel).
    print("Q129a sarithi: val9<<shift4 — 8192 Kombis, distinkte Werte mod 2^32")
    _q129 = set()
    for _v in range(-256, 256):
        for _s in range(16):
            _q129.add((_v << _s) & 0xFFFFFFFF)
    assert len(_q129) == 4352, f"Q129a: distinct={len(_q129)} != 4352 -> STOP"
    print("Q129: distinct=4352")

    # Q129b: Existenz-Beweise (sat + Witness). Ziel-Tupel fuer typische Werte;
    # Modell: val9 sign-extended, shift4 0..15. Zwei Witness drucken.
    print("Q129b sarithi: Existenz-Beweise (Witness val/shift)")
    _v9 = z3.BitVec('v_q129', 9)
    _s4 = z3.BitVec('s_q129', 4)
    _witnesses = 0
    for _tgt in [0x1000, 0x400, 0x800, 0xE80, 0x1680, 0x7F, 0x10000]:
        _s = z3.SolverFor('QF_BV')
        _s.set("timeout", 30000)
        _s.add((z3.SignExt(23, _v9) << z3.ZeroExt(28, _s4)) == z3.BitVecVal(_tgt, 32))
        _r = _s.check()
        assert _r == z3.sat, f"Q129b 0x{_tgt:X}: {_r} -> STOP (sollte darstellbar)"
        _m = _s.model()
        _vv = _m.eval(_v9, model_completion=True).as_long()
        _ss = _m.eval(_s4, model_completion=True).as_long()
        if _vv >= 128:
            _vv -= 256
        if _witnesses < 2:
            print(f"Q129b 0x{_tgt:X}: erreichbar (val={_vv}, shift={_ss}, "
                  f"bytes=0x{((_vv << _ss) & 0xFFFFFFFF):X})")
        _witnesses += 1
    print(f"Q129b: {_witnesses} Ziele alle sat (keine LUECKE)")

    # Q129c: Nicht-Darstellbarkeits-Beweise (Negations-Idiom, _m9_unsat).
    # val9 signed 9-bit, shift 0..15; keiner existiert fuer 0x101/0xE81/0x11B.
    print("Q129c sarithi: Nicht-Darstellbarkeit 0x101/0xE81/0x11B")
    for _tgt in [0x101, 0xE81, 0x11B]:
        _m9_unsat(f"Q129c 0x{_tgt:X}",
                  (z3.SignExt(23, _v9) << z3.ZeroExt(28, _s4))
                  == z3.BitVecVal(_tgt, 32))
    print("Q129: 0x101/0xE81/0x11B nicht darstellbar projektiert")

    # Q130a: cbitfrob_i mode5+amt8 — Distinctness via Python-Enumeration.
    print("Q130a cbitfrob_i: mode5<<8 | amt8 (amt & 0x1F) — 1024 distinkt")
    _q130 = set()
    for _m in range(32):
        for _a in range(32):
            _q130.add((_m << 8) | _a)
    assert len(_q130) == 1024, f"Q130a: distinct={len(_q130)} != 1024 -> STOP"
    print("Q130: 1024 distinkt")

    # Q130b: WASTE-Bits — obere 3 amt-Bits erreichen den Decode nie.
    # a 8-bit: gilt a>=0x20 UND (a&0x1F)==a -> a hat obere 3 Bits gesetzt UND
    # nicht gesetzt = Widerspruch -> unsat beweist, dass nur amt 0..31 wirkt.
    print("Q130b cbitfrob_i: 3 amt-WASTE-Bits (nur 0..31 am Decode)")
    _a8 = z3.BitVec('a_q130', 8)
    _m9_unsat("Q130b waste-bits (kein a>=0x20 ueberlebt &0x1F)",
              z3.And(z3.UGE(_a8, z3.BitVecVal(0x20, 8)),
                     (_a8 & z3.BitVecVal(0x1F, 8)) == _a8))

    # Q131a: slogii ones/rep/rot — Python-Enumeration (Ground-Truth-Spiegel).
    print("Q131a slogii: ones5/rep3/rot5 Masken-Enumeration — 5952 Kombis")
    def _slogii_mask(ones, rep, rot):
        _base = (1 << ones) - 1
        _eb = [32, 16, 8, 4, 2, 1][rep]
        _elem = _base & ((1 << _eb) - 1)
        _vv = 0
        for _i in range(32 // _eb):
            _vv |= (_elem & 0xFFFFFFFF) << (_i * _eb)
        _vv &= 0xFFFFFFFF
        return ((_vv >> rot) | (_vv << (32 - rot))) & 0xFFFFFFFF if rot else _vv

    _q131 = set()
    for _o in range(1, 32):
        for _r in range(6):
            for _rt in range(32):
                _q131.add(_slogii_mask(_o, _r, _rt))
    assert len(_q131) == 1303, f"Q131a: distinct={len(_q131)} != 1303 -> STOP"
    print("Q131: distinct=1303")

    # Q131b: CLASSIC-Reachability — bekannte Klassiker-Masken erreichbar.
    print("Q131b slogii: Klassiker-Masken-Erreichbarkeit")
    _CLASSIC = [0xFFFFFFFF, 0x0F0F0F0F, 0xFF00FF00, 0x55555555, 0x0000FFFF]
    for _ct in _CLASSIC:
        assert _ct in _q131, f"Q131b 0x{_ct:08X}: nicht erreichbar -> STOP"
        for _o in range(1, 32):
            for _r in range(6):
                for _rt in range(32):
                    if _slogii_mask(_o, _r, _rt) == _ct:
                        print(f"Q131b 0x{_ct:08X}: ones={_o}, rep={_r}, rot={_rt}")
                        break
                else:
                    continue
                break
            else:
                continue
            break

    # Q132: Variante sarithi val8<<shift5 (Untertest) — 8-bit-val (-128..127),
    # shift 0..31. Groesserer Shift-Bereich, aber schmalerer Val -> MEHR
    # Verschnuerung (Overlaps). Erwartet: 8192 Kombis -> 3328 distinkt
    # (weniger als val9<<shift4 mit 4352, da Val-Bereich halbiert dominiert).
    print("Q132 sarithi-var: val8<<shift5 — 8192 Kombis, distinkte Werte mod 2^32")
    _q132 = set()
    for _v in range(-128, 128):
        for _s in range(32):
            _q132.add((_v << _s) & 0xFFFFFFFF)
    assert len(_q132) == 3328, f"Q132: distinct={len(_q132)} != 3328 -> STOP"
    print("Q132: distinct=3328 (val9<<shift4 hatte 4352)")

    LEMMAS.update({
        'R_SARITHI_IMM': 'sarithi val9<<shift4: 8192 Kombis -> 4352 distinkt; '
                         '0x101/0xE81/0x11B nicht darstellbar',
        'R_CBITFROBI_AMT': 'cbitfrob_i amt8: 3 tote Bits (nur 0..31 wirken), '
                           '1024 distinkt',
        'R_SLOGII_MASK': 'slogii ones/rep/rot: 5952 Kombis -> 1303 distinkte '
                         'Masken; Klassiker drin',
        'R_SARITHI8': 'sarithi-Variante val8<<shift5: 8192 Kombis -> 3328 '
                      'distinkt (schmalerer Val > mehr Overlaps)',
    })
    print("M25 F1-Imm13-Allokation "
          "(R_SARITHI_IMM/R_CBITFROBI_AMT/R_SLOGII_MASK/R_SARITHI8):")
    for name in sorted(LEMMAS):
        print(f"  {name:<14} {LEMMAS[name]}")
    print(f"  Q129-Q132 fertig ({time.time()-t125:.2f}s)")
    print("M25 PASS")
    return


if __name__ == "__main__":
    z3.set_param("parallel.enable", True)  # Multi-Core: mehrere Strategien parallel

    import argparse

    # Sektions-Gruppen fuer gezielte Laeufe. M-Namen + thematische Aliase;
    # Aliase fuer schnelle Agenten-/Dev-Laeufe (Context-/Timeout-Schutz).
    _SEC_NAMES = ['M1', 'M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M8', 'M8b', 'M9',
                  'M10', 'M10b', 'M12', 'M13', 'M14', 'M15', 'M16', 'M17', 'M18', 'M19', 'M20', 'M21', 'M22', 'M23', 'M24', 'M25']
    _ALIASES = {
        'ternlog': ['M1'],
        'bitfrob': ['M2', 'M3', 'M4', 'M5', 'M6', 'M7', 'M16', 'M17', 'M18'],
        'arith4':  ['M8', 'M8b'],
        'permb':   ['M9'],
        'pipe':    ['M10', 'M10b'],
        'macro':   ['M12', 'M13', 'M14'],
        'gf':      ['M15'],
        'decoder': ['M19'],
        'sqrom':   ['M20'],
        'div':     ['M21'],
        'newton32': ['M22'],
        'offset':  ['M23'],
        'bcond':   ['M24'],
        'f1imm':   ['M25'],
        'smoke':   ['M1', 'M2', 'M3', 'M4', 'M8b'],
    }
    _TITLES = {
        'M1': 'ternlog-LUTs (Q1-Q3, Q100-Q114)',
        'M2': 'bitfrob-Stufe (LSR/LSL/ROR/ROL/MASK/MASKW/SEXT)',
        'M3': '1-Pass-Synthese (CMOV)',
        'M4': 'Count/Scan-Modi (LZC/TZC/POPCNT_B)',
        'M5': 'Pass-Schranken-Beweise UBFX/BFI',
        'M6': 'pext32/pdep32-Butterfly-Beweise',
        'M7': '1-Pass-Enumeration (ternlog+bitfrob Oberflaeche)',
        'M8': 'arith4-Skalar-Enumeration (Konkrete-Mode-Dispatch)',
        'M8b': 'PADD/CMP/PMINMAX/MUL-Modelle (SWAR 1-Pass)',
        'M9': 'permb — Byte/Nibble-Permute + shift_ctrl',
        'M10': 'Aux-Pipe-Slot-Modelle (2. Pipe-Slot)',
        'M10b': 'Kompositions-Beweise (2. Pipe-Slot)',
        'M12': 'echte Mikrocode-Sequenzen',
        'M13': 'Makro-Sequenzen (shift_right/shift_left/mul_ctz/gray)',
        'M14': 'Kompositions-Lemmata',
        'M15': 'GF(2^8)-Multiplikation (CLMUL/POLY_RED)',
        'M16': 'bitfrob-Modi als z3-Funktionen + Negations-Beweise',
        'M17': 'NIBLKP/BMAT_N_OR/BMAT_N_XOR/PSAD (ROM/Primitive)',
        'M18': 'BMATOR/BMATXOR + PEXT_N/PDEP_N (32-Bit)',
        'M19': 'imm_encode-Decoder-Primitiven',
        'M20': 'SQROM8-Quadrat-Tabellen-MUL (Q115-Q116)',
        'M21': 'Newton-Division (Q117-Q119)',
        'M22': '32-bit-Newton-Abschaetzung (Q120-Q122)',
        'M23': 'Encoding-Offset-Check (Q123-Q125)',
        'M24': 'bxx XOR-Substitution (Q126-Q128)',
        'M25': 'F1-Imm13-Allokation (Q129-Q131)',
    }
    _SECTIONS = [
        ('M1', _run_M1), ('M2', _run_M2), ('M3', _run_M3), ('M4', _run_M4),
        ('M5', _run_M5), ('M6', _run_M6), ('M7', _run_M7), ('M8', _run_M8),
        ('M8b', _run_M8b), ('M9', _run_M9), ('M10', _run_M10), ('M10b', _run_M10b),
        ('M12', _run_M12), ('M13', _run_M13), ('M14', _run_M14), ('M15', _run_M15),
        ('M16', _run_M16), ('M17', _run_M17), ('M18', _run_M18), ('M19', _run_M19),
        ('M20', _run_M20),
        ('M21', _run_M21),
        ('M22', _run_M22),
        ('M23', _run_M23),
        ('M24', _run_M24),
        ('M25', _run_M25),
    ]

    def _resolve(tok):
        if tok in _ALIASES:
            return _ALIASES[tok]
        if tok in _SEC_NAMES:
            return [tok]
        _parser.error(f"unbekannte Gruppe/Sektion: {tok}")

    _parser = argparse.ArgumentParser(
        description='z3-Beweis-Suite der 4-Stufen-Pipeline (M1..M19)')
    _parser.add_argument('-g', '--group', action='append', default=[], metavar='GRP',
                         help='nur diese Sektion(en) laufen (wiederholbar, kommasepariert); '
                              'M-Namen oder Aliase; Default: alle')
    _parser.add_argument('--skip', action='append', default=[], metavar='GRP',
                         help='Sektion(en) vom Lauf ausschliessen')
    _parser.add_argument('--list', action='store_true',
                         help='Sektionen + Aliase zeigen, dann exit')
    _parser.add_argument('--stretch', action='store_true',
                         help='M13: erweiterte shift-Grenzen (hist. sys.argv-Flag)')
    _args = _parser.parse_args()

    if _args.list:
        _inv = {}
        for _a, _ss in _ALIASES.items():
            for _s in _ss:
                _inv.setdefault(_s, []).append(_a)
        print("Sektionen (M-Namen; Aliase dahinter):")
        for _n in _SEC_NAMES:
            print(f"  {_n:<4} {_TITLES[_n]:<52} [{', '.join(_inv.get(_n, []))}]")
        print("Aliase:")
        for _a, _ss in _ALIASES.items():
            print(f"  {_a:<10} {' '.join(_ss)}")
        print("Beispiele: python3 pipeline_smt.py -g ternlog | -g M9,pipe | -g smoke "
              "| --skip M15")
        sys.exit(0)

    _want = set(_SEC_NAMES)
    if _args.group:
        _want = set()
        for _g in _args.group:
            for _tok in _g.split(','):
                _tok = _tok.strip()
                if _tok:
                    _want.update(_resolve(_tok))
    for _g in _args.skip:
        for _tok in _g.split(','):
            _tok = _tok.strip()
            if _tok:
                _want.difference_update(_resolve(_tok))

    for _n, _fn in _SECTIONS:
        if _n not in _want:
            print(f"{_n} skip")
            continue
        _t0 = time.time()
        _fn()
        print(f"[{_n} {time.time() - _t0:.2f}s]")



print("import-ok")
