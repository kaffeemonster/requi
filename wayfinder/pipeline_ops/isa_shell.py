"""isa_shell.py — Rumpf-Pipeline um die Kern-Pipeline (pipeline.py).

Sandwich-Simulator fuer die Papier-Encoding-Entwuerfe aus isa_vision.md:
    fetch -> decode -> [permb -> bitfrob -> ternlog -> arith4] -> writeback
Die Kern-Stufen kommen aus pipeline.py (execute_pipeline); diese Shell ergaenzt
PC, Register-File (C/S-Gruppen), Memory (RAM + MSR-pseudo-MMIO @ Top) und einen
rudimentaeren Decoder fuer die ISA-Formen.

ITERATION 1 (Kern-Zyklus): carith (F3) + sarith (F2-Sub) + Control (bra/brl/bxx)
+ Memory (ld/st). ternlog/permb/bitfrob-Planen: Lexikon reserviert, Exec folgt.

VEREINFACHUNGEN (Iteration 1, sind in isa_vision.md als offen markiert):
- bxx: XOR-Substitutions-Bedingung (Lemma R_BCOND_NOW, pipeline_smt.py M24):
  src1[3:2] = Ersatz-Kanal p, src1[1:0] = Paar (0:S^O, 1:C^Z, 2:S^Z, 3:C^O);
  dst Bit4 = inv (0: any ((f_eff^wish)&mask)!=mask, 1: all ==0).
- PC-relative: src1-Feld = 0 (S0, Zero-Reg) bedeutet PC-Basis.
- Memory-Adresse: base + idx + (offs << scale); Index byte-genau (unaligned),
  Offset breiten-skaliert (ARM-LDR-artig). Control: base + (idx << scale) + (offs*2 << scale).
- 1 Cycle/Instruktion (keine Pipeline-Stalls).
- unsigned-Signal: Assembler-Parameter (Encoding-Position im carith noch offen).
- MSR-Region (0xFFFFF000-0xFFFFFFFF, Top): Reset-Vektor = letztes Wort 0xFFFFFFFC,
  via ld zero_reg + negativer Offset; Bottom 0x0 frei fuer Vektor-Tabellen.
  Vektor/IDENT/FLAGS/PC/CYCLE lesbar, Schreiben ignoriert.
"""
import struct as _struct

from pipeline import (
    ArithMode, BitFrobMode, TernLut, OpType,
    FLAG_S, FLAG_C, FLAG_Z, FLAG_O,
    execute_pipeline,
)

# ---------------------------------------------------------------------------
# Encoding-Lexikon (PAPIER-Entwuerfe isa_vision.md, umsortier-freundlich)
# FORMS: Feldname -> (hi_bit, lo_bit). Decoder liest nur hier.
# ---------------------------------------------------------------------------
FORMS = {
    'F3':   {'src3': (25, 22), 'dst': (21, 17), 'src1': (16, 13), 'src2': (12, 9),
             'cst': (8, 8), 'ctrl': (7, 0)},
    'F2':   {'subop': (25, 22), 'dst': (21, 17), 'src1': (16, 13), 'src2': (12, 9),
             'cst': (8, 8), 'ctrl': (7, 0)},
    'F1':   {'subop': (25, 22), 'dst': (21, 17), 'src1': (16, 13), 'imm': (12, 0)},
    'F2C':  {'subop': (25, 22), 'dst': (21, 17), 'src1': (16, 13), 'imm': (12, 0)},
    'FMEM': {'scale': (25, 24), 'off_hi': (23, 22), 'dst': (21, 17),
             'src1': (16, 13), 'src2': (12, 9), 'off_lo': (8, 0)},
    'FLDI': {'dst': (25, 21), 'form': (20, 20), 'imm': (19, 0)},
}

# PLANES: plane-Feld (30-26) -> (Form, Semantik)
PLANES = {
    0x0: ('F3', 'carith'),
    0x1: ('F3', 'ternlog'),
    0x2: ('F3', 'permb'),
    0x3: ('F3', 'bitfrob'),
    0x4: ('F2', 'subsplit'),   # Sub-Plane: 16 Sub-Instruktionen (c/s-Varianten)
    0x5: ('FMEM', 'control'),
    0x6: ('FMEM', 'memory'),
    0x7: ('FLDI', 'ldi'),
    0x8: ('F2C', 'csubsplit'),  # csubsplit (Complex-Subsplit, C-Pendant zu Plane 0x4, F1-Imm-Familie)
    # 0x9-0xF: frei (System/MSR, AMOD, float, MOVEM, ...)
}

# SUBOPS: 4-Bit-Sub-Opcode -> Instruktionsname. Option (a): eigener Slot je C/S.
# Form je Slot: 0x0-0x7 = F2 (2-Op), 0x8-0xB = F1 (Imm13), 0xC-0xF = frei.
# OFFEN (Encoding-Frage): F1/sarithi hat KEIN Mode-Feld (Sub-Op+dst+src1+Imm13
# = 32 Bit). Iteration 1: sarithi = ADD-only (Immediate-Cousin fuer Pointer-
# Offsets ist primär additiv). Aufloesung: Mode in Sub-Op-Slots oder ins Imm.
SUBOPS = {
    0x0: ('sarith', 's', 'F2'),   0x1: ('sarith', 'c', 'F2'),
    0x2: ('slogi', 's', 'F2'),    0x3: ('slogi', 'c', 'F2'),
    0x4: ('sbitfrob', 's', 'F2'), 0x5: ('sbitfrob', 'c', 'F2'),
    0x6: ('sshufb', 's', 'F2'),   0x7: ('sshufb', 'c', 'F2'),
    0x8: ('sarith', 's', 'F1'),   0x9: ('sarith', 'c', 'F1'),
    0xA: ('slogii', 's', 'F1'),   0xB: ('slogii', 'c', 'F1'),   # AND
    0xC: ('slogii', 's', 'F1'),   0xD: ('slogii', 'c', 'F1'),   # OR
    0xE: ('slogii', 's', 'F1'),   0xF: ('slogii', 'c', 'F1'),   # XOR
}
# slogii-Op: Bit1/2 kodieren 0=AND 1=OR 2=XOR (sub 0xA-0xE, bit0 = s/c-Gruppe)
_SLOGII_OP = {0xA: 0x8, 0xC: 0xE, 0xE: 0x6}  # sub -> 2-Input-LUT (AND/OR/XOR)

# SUBOPS_C: csubsplit-Plane (0x8) Sub-Ops. Alle F1 (Imm13); C-Gruppe zentral.
SUBOPS_C = {
    0x8: ('cbitfrob', 'c', 'F1'),   # rest frei: cshufb_i, carith_i, ...
}

# cbitfrob_i-Shift-Familie: Spar-Core-Artefakt. amt<8 = 1 Passage (bitfrob fein);
# amt>=8 = 2 Passagen (permb-Byte-Grob + bitfrob-Fein, +1 Extra-Zyklus).
SHIFT_FAM = {BitFrobMode.LSR, BitFrobMode.LSL, BitFrobMode.ASR,
             BitFrobMode.ROR, BitFrobMode.ROL, BitFrobMode.SHR_STICKY}

# MSR-Region (pseudo-MMIO) am TOP des 32-Bit-Adressraums — via negativer
# Zero-Reg-Offsets erreichbar; Bottom (0x0) frei fuer Vektor-Tabellen.
MSR_BASE   = 0xFFFFF000   # Region-Basis (4K)
MSR_TOP    = 0x100000000  # exclusive
MSR_VECTOR = 0xFFFFFFFC   # Reset-Vektor: letztes Wort — ld zero, offs -2 (= -4 Bytes)
MSR_IDENT  = 0xFFFFFFF8   # Feature/Ident (lesbar)
MSR_FLAGS  = 0xFFFFFFF4   # Flags (lesbar)
MSR_PC     = 0xFFFFFFF0   # PC (lesbar)
MSR_CYCLE  = 0xFFFFFFEC   # Cycle-Counter (lesbar)
MSR_END    = 0x100000000  # Ende (exclusive), = MSR_TOP

RAM_SIZE = 0x10000
RESET_PC = 0x1000   # Default-Vektor (Code-Base; unveraendert gueltig)

# Bypass-Sub-ctrls (Muster aus helpers.py: prev_in_strobe=8 = durchreichen)
_BXX_PAIRS = ((0, 3), (1, 2), (0, 2), (1, 3))  # bxx-Paar-Kodierung: S^O, C^Z, S^Z, C^O
_b_perm = {'src3_idx': 0, 'cst_table': False, 'imm6': 0, 'mode_nibble': False,
           'blank_enable': False, 'prev_in_strobe': 8, 'write_flags': False,
           'read_flags': False, 'internal_table': False}
_b_bitf = {'mode_imm6': BitFrobMode.LSR, 'inv_1': False, 'inv_2': False, 'inv_3': False,
           'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False,
           'read_flags': False, 'internal_table': False}
_b_tern = {'tern_lut': 0x00, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False,
           'write_flags': False, 'read_flags': False, 'internal_table': False}
_b_arit = {'mode_imm6': ArithMode.ADD, 'inv_1': False, 'inv_2': False, 'inv_3': False,
           'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False,
           'read_flags': False, 'internal_table': False}


def _arith_ctrl(mode, inv1=False, inv2=False, inv3=False, wf=False, unsigned=False,
                op_type=OpType.SCALAR):
    """ctrl-Dict fuer den Kern: arith4 rechnet, die anderen 3 Stufen bypassen."""
    return {
        'permb': dict(_b_perm),
        'bitfrob': dict(_b_bitf),
        'ternlog': dict(_b_tern),
        'arith4': dict(_b_arit, mode_imm6=mode, inv_1=inv1, inv_2=inv2, inv_3=inv3,
                       prev_in_strobe=0, write_flags=wf, unsigned=unsigned,
                       op_type_1=op_type, op_type_2=op_type, op_type_3=op_type),
    }


# ---------------------------------------------------------------------------
# Assembler-Helper: bauen 32-Bit-Woerter aus den Lexikon-Formen
# ---------------------------------------------------------------------------
def _set_bits(word, field, value, form):
    hi, lo = form[field]
    mask = (1 << (hi - lo + 1)) - 1
    return word | ((value & mask) << lo)


# op_type-Lane-Erweiterungen fuer carith (PSAD.b etc). F3-ctrl ist VOLL
# (inv3<<7|inv2<<6|inv1<<5|mode5) — kein op_type-Feld (ISA-Frage, offen).
# TEMPORAERE Shell-Extension: op_type je Wort in externem Dict (nicht-Encoded).
_CARITH_LANE = {}

def carith_w(mode, dst, s1, s2, s3=0, inv1=False, inv2=False, inv3=False,
             cst=False, wrf=False, op_type=OpType.SCALAR):
    """F3 carith: ctrl = inv3<<7 | inv2<<6 | inv1<<5 | mode(5).
    op_type: extracodiert (nicht im 32-Bit-Word — F3 hat kein Lane-Feld,
    temporaere Shell-Extension via _CARITH_LANE)."""
    ctrl = (int(inv3) << 7) | (int(inv2) << 6) | (int(inv1) << 5) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 1 if cst else 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'plane', 0x0, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    if op_type != OpType.SCALAR:
        _CARITH_LANE[w] = op_type
    return w


def ternlog_w(lut, dst, s1, s2, s3=0, cst=False, wrf=False):
    """F3 ternlog: ctrl = LUT-Wert (256 Eintraege). cst=True: src3 = Pool-Index."""
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 1 if cst else 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', lut & 0xFF, FORMS['F3'])
    w = _set_bits(w, 'plane', 0x1, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def permb_w(mode, dst, s1, s2, s3, blank=False, cst=False, wrf=False):
    """F3 permb: ctrl = blank<<7 | mode(5). cst=True: src3 = Pool-Index."""
    ctrl = (0x80 if blank else 0) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 1 if cst else 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'plane', 0x2, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def bitfrob_w(mode, dst, s1, s2, s3=0, inv1=False, inv2=False, inv3=False, cst=False, wrf=False):
    """F3 bitfrob: ctrl = inv3<<7 | inv2<<6 | inv1<<5 | mode(5). cst=True: src3 = Pool-Index."""
    ctrl = (0x80 if inv1 else 0) | (0x40 if inv2 else 0) | (0x20 if inv3 else 0) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 1 if cst else 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'plane', 0x3, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def sarith_w(sub, mode, dst, s1, s2=0, inv1=False, inv2=False, inv3=False, wrf=False):
    """F2 sarith (Sub-Plane): ctrl = inv3<<7 | inv2<<6 | inv1<<5 | mode(5)."""
    ctrl = (int(inv3) << 7) | (int(inv2) << 6) | (int(inv1) << 5) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'subop', sub, FORMS['F2'])
    w = _set_bits(w, 'dst', dst, FORMS['F2'])
    w = _set_bits(w, 'src1', s1, FORMS['F2'])
    w = _set_bits(w, 'src2', s2, FORMS['F2'])
    w = _set_bits(w, 'cst', 0, FORMS['F2'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F2'])
    w = _set_bits(w, 'plane', 0x4, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def sarithi_w(sub, mode, dst, s1, val, shift=0, wrf=False):
    """F1 sarith_imm: val(9, sign-extended) << shift(4). wrf=True setzt Flags."""
    val9 = val & 0x1FF
    sh = shift & 0xF
    imm = (val9 << 4) | sh
    w = 0
    w = _set_bits(w, 'subop', sub, FORMS['F1'])
    w = _set_bits(w, 'dst', dst, FORMS['F1'])
    w = _set_bits(w, 'src1', s1, FORMS['F1'])
    w = _set_bits(w, 'imm', imm & 0x1FFF, FORMS['F1'])
    w = _set_bits(w, 'plane', 0x4, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def cbitfrob_i_w(mode, dst, s1, val, wrf=False):
    """F2C cbitfrob_i (Plane 0x8): mode5=(imm>>8), val=Shift-Menge (8-Bit, am
    Use auf 5 Bit gekappt). C-Gruppe. Shift-Familie = Spar-Core (1-2 Passagen)."""
    imm = ((mode & 0x1F) << 8) | (val & 0xFF)
    w = 0
    w = _set_bits(w, 'subop', 0x8, FORMS['F2C'])
    w = _set_bits(w, 'dst', dst, FORMS['F2C'])
    w = _set_bits(w, 'src1', s1, FORMS['F2C'])
    w = _set_bits(w, 'imm', imm & 0x1FFF, FORMS['F2C'])
    w = _set_bits(w, 'plane', 0x8, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def ctrl_w(dst, s1, s2, offs, scale=0, wrf=False):
    """FMEM control: offs = 11-Bit signed in 2-Byte-Einheiten. dst=0+WRF=0 bra,
    dst=Maske+WRF=1 bxx, dst!=0+WRF=0 brl."""
    offs &= 0x7FF  # 11 Bit signed (2er-Komplement)
    w = 0
    w = _set_bits(w, 'scale', scale & 3, FORMS['FMEM'])
    w = _set_bits(w, 'off_hi', (offs >> 9) & 3, FORMS['FMEM'])
    w = _set_bits(w, 'dst', dst, FORMS['FMEM'])
    w = _set_bits(w, 'src1', s1, FORMS['FMEM'])
    w = _set_bits(w, 'src2', s2, FORMS['FMEM'])
    w = _set_bits(w, 'off_lo', offs & 0x1FF, FORMS['FMEM'])
    w = _set_bits(w, 'plane', 0x5, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def slogii_w(op, dst, s1, ones, rep, rot, wrf=False):
    """F1 slogii: [ones(5)|rep(3)|rot(5)] Muster + Logik-Op.
    op: 'and'/'or'/'xor' (bestimmt LUT2).
    tsti-Pseudo-Op: slogii_w('and', 0, s1, 0,0,0, wrf=True)."""
    _OP_LUT = {'and': 0xA, 'or': 0xC, 'xor': 0xE}  # F2-Sub-Op (bit0=s/c)
    if op not in _OP_LUT:
        raise ValueError(f"slogii: unbekannter op '{op}', erwartet and/or/xor")
    sub = _OP_LUT[op] | 0  # s-Variante (bit0=0)
    imm = ((ones & 0x1F) << 8) | ((rep & 7) << 5) | (rot & 0x1F)
    w = 0
    w = _set_bits(w, 'subop', sub, FORMS['F1'])
    w = _set_bits(w, 'dst', dst, FORMS['F1'])
    w = _set_bits(w, 'src1', s1, FORMS['F1'])
    w = _set_bits(w, 'imm', imm & 0x1FFF, FORMS['F1'])
    w = _set_bits(w, 'plane', 0x4, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def _build_mask_13(ones, rep, rot):
    """LDI-MASK-Formel in 13-Bit: (1<<ones)-1 -> Element -> replizieren -> rot.
    Kein inv (Komplement via LDI-MASK + Reg-slogi)."""
    ones = max(0, min(ones, 31))
    rep = max(0, min(rep, 5))
    rot = max(0, min(rot, 31))
    elem_bits = {0: 32, 1: 16, 2: 8, 3: 4, 4: 2, 5: 1}[rep]
    base = (1 << ones) - 1  # konsekutive 1er (wie BITFROB-MASKW pipeline.py:106)
    elem = base & ((1 << elem_bits) - 1)
    v = 0
    for i in range(32 // elem_bits):
        v |= (elem << (i * elem_bits))
    v = ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF  # Rechts-Rot
    return v


def ldi_movx_w(dst, imm16, hw=0, inv=False, sext=False, wrf=False):
    """FLDI F=0 MOVX: imm16 an Halbwort-Position hw (0-3), inv/sext-Bits.
    WRF: 0=zero-fill (nur diese haelfte), 1=merge (Rest bleibt)."""
    w = 0
    w = _set_bits(w, 'dst', dst, FORMS['FLDI'])
    w = _set_bits(w, 'form', 0, FORMS['FLDI'])
    imm = ((hw & 3) << 18) | ((0x10000 if sext else 0)) | ((0x20000 if inv else 0)) | (imm16 & 0xFFFF)
    w = _set_bits(w, 'imm', imm, FORMS['FLDI'])
    w = _set_bits(w, 'plane', 0x7, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def ldi_mask_w(dst, ones, rep, rot, inv=False, wrf=False):
    """FLDI F=1 MASK: (1<<ones)-1 repliziert (rep: 0=32/1=16/2=8/3=4/4=2/5=1-Bit-Elem),
    rot=Rechtsrotation, inv=invertieren. WRF: 0=ersetzen, 1=merge mit alt."""
    w = 0
    w = _set_bits(w, 'dst', dst, FORMS['FLDI'])
    w = _set_bits(w, 'form', 1, FORMS['FLDI'])
    imm = ((ones & 0x1F) << 15) | ((rep & 7) << 12) | ((rot & 0x1F) << 7) | ((1 if inv else 0) << 6)
    w = _set_bits(w, 'imm', imm, FORMS['FLDI'])
    w = _set_bits(w, 'plane', 0x7, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def bitrev_bam(dst, idx, base, n):
    """BITREV_BAM (Makro, FFT-Adressgenerierung): dst = base | reverse-low-N(idx).
    reverse-low-N(x) = BITREV8(x) >> (8-n); idx und base sind C-Register
    (bitfrob/ternlog lesen die C-Gruppe). Vorbedingung: idx < 2^n und base in
    den unteren n Bit = 0 (aligned) -> OR ist ein sauberer Merge.
    Zersetzung (2-3 Instr): BITREV8 + cbitfrob_i LSR#(8-n) + ternlog OR.
    Fuer n>8 waere zusaetzlich Byte-Reverse (permb) noetig (nicht abgedeckt)."""
    if not 0 <= n <= 8:
        raise ValueError("bitrev_bam: n muss 0..8 sein")
    seq = [bitfrob_w(BitFrobMode.BITREV8, dst, idx, 0)]
    if n < 8:
        seq.append(cbitfrob_i_w(BitFrobMode.LSR, dst, dst, 8 - n))
    seq.append(ternlog_w(TernLut.OR, dst, dst, base, 0))
    return seq


def bxx_w(mask, wish, chan, pair, offs, scale=0, inv=False, neg=False):
    """bxx: mask=4-Bit-Flagmaske, wish=4-Bit-Soll, chan=Ersatz-Kanal (0-3),
    pair=Paar (0:S^O,1:C^Z,2:S^Z,3:C^O), inv=any/all. src1=(chan<<2)|pair.
    neg=True: Negation via wish^=mask + inv-Flip (XOR-Algebra, M24-Beweis).
    Semantisch exakt das Komplement; Word-Kodierung kann von aehnlichen
    Wrappern abweichen (any/all-Darstellung frei waehlbar)."""
    if neg:
        wish = wish ^ (mask & 0xF)
        inv = not inv
    dst = (mask & 0xF) | (0x10 if inv else 0)
    return ctrl_w(dst, (chan & 3) << 2 | (pair & 3), wish & 0xF, offs, scale=scale, wrf=True)


# ---------------------------------------------------------------------------
# 14 ARM-condition convenience wrappers over bxx_w (XOR-substitution model,
# see isa_vision.md §3 / M24).
# ---------------------------------------------------------------------------

def bxx_eq(offs, scale=0):
    """EQ — Z==1."""
    return bxx_w(0x04, 0x04, 0, 0, offs, scale, inv=True)


def bxx_ne(offs, scale=0):
    """NE — Z==0."""
    return bxx_w(0x04, 0x00, 0, 0, offs, scale, inv=True)


def bxx_cs(offs, scale=0):
    """CS — C==1."""
    return bxx_w(0x02, 0x02, 0, 0, offs, scale, inv=True)


def bxx_cc(offs, scale=0):
    """CC — C==0."""
    return bxx_w(0x02, 0x00, 0, 0, offs, scale, inv=True)


def bxx_mi(offs, scale=0):
    """MI — S==1."""
    return bxx_w(0x01, 0x01, 2, 0, offs, scale, inv=True)


def bxx_pl(offs, scale=0):
    """PL — S==0."""
    return bxx_w(0x01, 0x00, 2, 0, offs, scale, inv=True)


def bxx_vs(offs, scale=0):
    """VS — O==1."""
    return bxx_w(0x08, 0x08, 0, 0, offs, scale, inv=True)


def bxx_vc(offs, scale=0):
    """VC — O==0."""
    return bxx_w(0x08, 0x00, 0, 0, offs, scale, inv=True)


def bxx_hi(offs, scale=0):
    """HI — C==1 and Z==0."""
    return bxx_w(0x06, 0x02, 0, 0, offs, scale, inv=True)


def bxx_ls(offs, scale=0):
    """LS — C==0 or Z==1."""
    return bxx_w(0x06, 0x04, 0, 0, offs, scale, inv=False)


def bxx_ge(offs, scale=0):
    """GE — S==O."""
    return bxx_w(0x01, 0x00, 0, 0, offs, scale, inv=True)


def bxx_lt(offs, scale=0):
    """LT — S!=O."""
    return bxx_w(0x01, 0x01, 0, 0, offs, scale, inv=True)


def bxx_gt(offs, scale=0):
    """GT — S==O and Z==0."""
    return bxx_w(0x06, 0x00, 1, 0, offs, scale, inv=True)


def bxx_le(offs, scale=0):
    """LE — S!=O or Z==1."""
    return bxx_w(0x06, 0x0E, 1, 0, offs, scale, inv=False)


def mem_w(dst, s1, s2, offs, scale, wrf=False):
    """FMEM memory: WRF=0 ld, 1 st. offs = 11-Bit signed in Breiten-Einheiten."""
    offs &= 0x7FF
    w = 0
    w = _set_bits(w, 'scale', scale & 3, FORMS['FMEM'])
    w = _set_bits(w, 'off_hi', (offs >> 9) & 3, FORMS['FMEM'])
    w = _set_bits(w, 'dst', dst, FORMS['FMEM'])
    w = _set_bits(w, 'src1', s1, FORMS['FMEM'])
    w = _set_bits(w, 'src2', s2, FORMS['FMEM'])
    w = _set_bits(w, 'off_lo', offs & 0x1FF, FORMS['FMEM'])
    w = _set_bits(w, 'plane', 0x6, {'plane': (30, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (31, 31)})
    return w


def _sign11(x):
    x &= 0x7FF
    return x - 0x800 if x & 0x400 else x


def _sign13(x):
    x &= 0x1FFF
    return x - 0x2000 if x & 0x1000 else x


def _sign9(x):
    """Sign-extend a 9-bit value."""
    x &= 0x1FF
    return x - 0x200 if x & 0x100 else x


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------
class ShellCPU:
    """RF (C0-C15/S0-S15, C0/S0=Zero), PC, FLAGS, RAM 64K @ 0x0 + MSR @ Top, Zaehler."""

    def __init__(self, ram_size=RAM_SIZE, ident=0x00000001):
        self.rf = [0] * 32
        self.pc = RESET_PC
        self.flags = 0
        self.ram = bytearray(ram_size)
        self.cycle = 0
        self.ident = ident
        self.op_counts = {}
        self.halted = False
        # Reset-Vektor (Wort an MSR_VECTOR @ Top) = RESET_PC; nicht RAM-gekoppelt
        self.msr_vector = RESET_PC

    # -- Register-File -----------------------------------------------------
    def read_dst(self, i):
        i &= 0x1F
        return 0 if i in (0, 16) else self.rf[i]

    def read_c(self, i):
        i &= 0xF
        return 0 if i == 0 else self.rf[i]

    def read_s(self, i):
        i &= 0xF
        return 0 if i == 0 else self.rf[16 + i]

    def write_dst(self, i, val):
        i &= 0x1F
        if i not in (0, 16):  # Zero-Regs: Schreiben ins Nirvana
            self.rf[i] = val & 0xFFFFFFFF

    # -- Memory -------------------------------------------------------------
    def msr_read(self, addr):
        if addr == MSR_IDENT:
            return self.ident
        if addr == MSR_FLAGS:
            return self.flags
        if addr == MSR_PC:
            return self.pc
        if addr == MSR_CYCLE:
            return self.cycle
        if addr == MSR_VECTOR:
            return self.msr_vector
        return 0  # reserviert

    def mem_read(self, addr, size):
        if addr >= MSR_BASE:  # MSR-Region abfangen (Top)
            val = 0
            for i in range(size):
                a = addr + i  # Byte-Zugriffe wort-aligniert auf Register abbilden
                val |= ((self.msr_read(a & ~3) >> (8 * (a & 3))) & 0xFF) << (8 * i)
            return val
        off = addr
        if off + size > len(self.ram):
            raise ValueError(f"mem_read out of range: 0x{addr:x}+{size}")
        return int.from_bytes(self.ram[off:off + size], 'little')

    def mem_write(self, addr, size, val, warn=True):
        if MSR_BASE <= addr < MSR_TOP:
            if warn:
                print(f"WARN: mem_write in MSR-Region verworfen: 0x{addr:x} size={size}")
            return  # MSR-Region schreibgeschuetzt (Iteration 1)
        off = addr
        if off + size > len(self.ram):
            raise ValueError(f"mem_write out of range: 0x{addr:x}+{size}")
        self.ram[off:off + size] = (val & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')

    # -- Decode -------------------------------------------------------------
    def decode(self, word):
        wf = (word >> 31) & 1
        plane = (word >> 26) & 0x1F
        plane_entry = PLANES[plane]
        form_name, sem = plane_entry
        form = FORMS[form_name]
        dec = {'wf': wf, 'plane': plane, 'form': form_name, 'sem': sem,
               'plane_entry': plane_entry, '__word__': word}
        if form_name == 'FMEM':
            dec['scale_e'] = (word >> 24) & 3
            dec['offs'] = _sign11(((word >> 22) & 3) << 9 | (word & 0x1FF))
            dec['dst'] = (word >> 17) & 0x1F
            dec['src1'] = (word >> 13) & 0xF
            dec['src2'] = (word >> 9) & 0xF
        elif form_name == 'F3':
            dec['src3'] = (word >> 22) & 0xF
            dec['dst'] = (word >> 17) & 0x1F
            dec['src1'] = (word >> 13) & 0xF
            dec['src2'] = (word >> 9) & 0xF
            dec['cst'] = (word >> 8) & 1
            dec['ctrl'] = word & 0xFF
        elif form_name == 'F2':  # Sub-Split-Plane: Sub-Op bestimmt die echte Form
            sub = (word >> 22) & 0xF
            dec['sub'] = sub
            try:
                _iname, _igroup, sub_form = SUBOPS[sub]
            except KeyError:
                raise NotImplementedError(f"Sub-Op 0x{sub:x} nicht belegt")
            dec['sub_form'] = sub_form
            if sub_form == 'F1':  # i-Version: src2 -> Imm13 (roh)
                dec['dst'] = (word >> 17) & 0x1F
                dec['src1'] = (word >> 13) & 0xF
                dec['imm'] = word & 0x1FFF  # roh: Interpretation je Sub-Op
            else:  # F2: 2-Op + ctrl
                dec['dst'] = (word >> 17) & 0x1F
                dec['src1'] = (word >> 13) & 0xF
                dec['src2'] = (word >> 9) & 0xF
                dec['cst'] = (word >> 8) & 1
                dec['ctrl'] = word & 0xFF
        elif form_name == 'F2C':  # csubsplit: Sub-Op -> c-Instruktion (alle F1)
            sub = (word >> 22) & 0xF
            dec['sub'] = sub
            dec['sub_form'] = 'F1'
            try:
                SUBOPS_C[sub]
            except KeyError:
                raise NotImplementedError(f"csubsplit Sub-Op 0x{sub:x} nicht belegt")
            dec['dst'] = (word >> 17) & 0x1F
            dec['src1'] = (word >> 13) & 0xF
            dec['imm'] = word & 0x1FFF  # roh: Interpretation je Sub-Op
        elif form_name == 'FLDI':
            dec['dst'] = (word >> 21) & 0x1F
            dec['form'] = (word >> 20) & 1
            dec['imm'] = word & 0xFFFFF
        return dec

    # -- Execute ------------------------------------------------------------
    def _arith(self, mode, a, b, c, inv1, inv2, inv3, wf, unsigned=False,
               op_type=OpType.SCALAR):
        out = execute_pipeline(a, b, c, _arith_ctrl(mode, inv1, inv2, inv3, wf, unsigned,
                                                    op_type),
                               prev_in=0, flags_in=self.flags)
        return out['res'], out['flags']

    def _count(self, name):
        self.op_counts[name] = self.op_counts.get(name, 0) + 1

    def _exec_carith(self, dec):
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        inv1, inv2, inv3 = bool(ctrl & 0x20), bool(ctrl & 0x40), bool(ctrl & 0x80)
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        if dec['cst']:
            from pipeline import ARITH_CST
            c = ARITH_CST[dec['src3']]  # 4-Bit-Pool-Index
        else:
            c = self.read_c(dec['src3'])
        res, flags = self._arith(mode, a, b, c, inv1, inv2, inv3, bool(dec['wf']),
                                 op_type=_CARITH_LANE.get(dec['__word__'], OpType.SCALAR))
        if dec['wf']:
            self.flags = flags
        self.write_dst(dec['dst'], res)
        self._count(f"carith:{ArithMode(mode).name}")

    def _exec_ternlog(self, dec):
        from pipeline import ternlog, TERNLOG_CST
        lut = dec['ctrl']  # 8 Bit = voller 256-Eintraege-Ternaer-LUT-Wert
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        if dec['cst']:
            c = TERNLOG_CST[dec['src3']] & 0xFFFFFFFF  # 4-Bit-Pool-Index, LUT waehlt
        else:
            c = self.read_c(dec['src3'])
        res = ternlog(a, b, c, lut, self.flags, 0, 0, False, False, False)['res']
        self.write_dst(dec['dst'], res)
        self._count("ternlog")

    def _exec_permb(self, dec):
        from pipeline import permb, PERMB_CST, PERMB_NIB_CST
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        c = self.read_c(dec['src3'])
        if dec['cst']:
            # cst-Pool: PERMB_CST (byte) oder PERMB_NIB_CST (nibble) via src3-Index
            c = (PERMB_NIB_CST if mode == 1 else PERMB_CST)[dec['src3']] & 0xFFFFFFFF
        if mode == 0:  # Byte-Permutation: src3 = Index-Vektor
            out = permb(a, b, c, 0, False, 0, self.flags,
                        blank_enable=bool(ctrl & 0x80))
        elif mode == 1:  # Nibble-Modus
            out = permb(a, b, c, 0, False, 0, self.flags, mode_nibble=True)
        elif mode == 2:  # Shift-Right: src3 = Shift-Menge 0..31
            out = permb(a, b, c, 0, False, 0, self.flags,
                        shift_ctrl=True, shift_left=False)
        elif mode == 3:  # Shift-Left
            out = permb(a, b, c, 0, False, 0, self.flags,
                        shift_ctrl=True, shift_left=True)
        else:
            raise NotImplementedError(f"permb-Mode {mode} noch nicht in Shell (Iteration 1)")
        self.write_dst(dec['dst'], out['res'])
        self._count(f"permb:{mode}")

    def _exec_bitfrob(self, dec):
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        inv1, inv2, inv3 = bool(ctrl & 0x80), bool(ctrl & 0x40), bool(ctrl & 0x20)
        from pipeline import bitfrob, BITFROB_CST
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        if dec['cst']:
            c = BITFROB_CST[dec['src3']]  # 4-Bit-Pool-Index (src3_idx, volle Breite)
        else:
            c = self.read_c(dec['src3'])
        out = bitfrob(a, b, c, mode, self.flags, inv_1=inv1, inv_2=inv2, inv_3=inv3,
                      write_flags=bool(dec['wf']))
        if dec['wf']:
            self.flags = out['flags']
        self.write_dst(dec['dst'], out['res'])
        self._count(f"bitfrob:{BitFrobMode(mode).name}")

    def _exec_sarith(self, dec):
        if dec['sub_form'] == 'F2':
            ctrl = dec['ctrl']
            mode = ctrl & 0x1F
            inv1, inv2, inv3 = bool(ctrl & 0x20), bool(ctrl & 0x40), bool(ctrl & 0x80)
            a = self.read_s(dec['src1'])
            b = self.read_s(dec['src2'])
            c = 0
        else:  # F1: val(9, sext) << shift(4)
            mode = ArithMode.ADD
            inv1 = inv2 = inv3 = False
            a = self.read_s(dec['src1'])
            imm = dec['imm'] & 0x1FFF
            val = _sign9((imm >> 4) & 0x1FF)
            shift = imm & 0xF
            b = (val << shift) & 0xFFFFFFFF
            c = 0
        res, flags = self._arith(mode, a, b, c, inv1, inv2, inv3, bool(dec['wf']))
        if dec['wf']:
            self.flags = flags
        self.write_dst(dec['dst'], res)
        self._count(f"sarith:{ArithMode(mode).name}")

    def _exec_slogi(self, dec):
        # Iteration 1: ternlog-2-Op via imm4 (16 LUTs) oder src2. ctrl low-4 = LUT.
        lut = dec['ctrl'] & 0xF  # 2-Input-LUT-Teil (16 Funktionen)
        lut8 = _expand_lut2(lut)
        from pipeline import ternlog
        a = self.read_c(dec['src1']) if dec['sub'] & 1 else self.read_s(dec['src1'])
        b = self.read_c(dec['src2']) if dec['sub'] & 1 else self.read_s(dec['src2'])
        res = ternlog(a, b, 0, lut8, self.flags, 0, 0, False, False, False)['res']
        self.write_dst(dec['dst'], res)
        self._count("slogi")

    def _exec_slogii(self, dec):
        """F1 slogii: [ones(5)|rep(3)|rot(5)] Muster + Logik-Op (AND/OR/XOR).
        tsti-Pseudo-Op: dst=0 + WRF=1 setzt Flags ohne Write."""
        imm = dec['imm'] & 0x1FFF
        ones = (imm >> 8) & 0x1F
        rep = (imm >> 5) & 7
        rot = imm & 0x1F
        mask = _build_mask_13(ones, rep, rot)
        from pipeline import ternlog
        a = self.read_c(dec['src1']) if dec['sub'] & 1 else self.read_s(dec['src1'])
        lut4 = _SLOGII_OP.get(dec['sub'] & 0xE, 0x8)  # AND/OR/XOR
        lut8 = _expand_lut2(lut4)
        out = ternlog(a, mask, 0, lut8, self.flags, 0, 0, bool(dec['wf']), False, False)
        if dec['wf']:
            self.flags = out['flags']
        self.write_dst(dec['dst'], out['res'])
        self._count("slogii")

    def _exec_sbitfrob(self, dec):
        # 2-Op-bitfrob: c=0 (kein src3 in F2). Gruppe via sub&1 (0=s, 1=c).
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        inv1, inv2, inv3 = bool(ctrl & 0x80), bool(ctrl & 0x40), bool(ctrl & 0x20)
        from pipeline import bitfrob
        a = self.read_c(dec['src1']) if dec['sub'] & 1 else self.read_s(dec['src1'])
        b = self.read_c(dec['src2']) if dec['sub'] & 1 else self.read_s(dec['src2'])
        out = bitfrob(a, b, 0, mode, self.flags, inv_1=inv1, inv_2=inv2, inv_3=inv3,
                      write_flags=bool(dec['wf']))
        if dec['wf']:
            self.flags = out['flags']
        self.write_dst(dec['dst'], out['res'])
        self._count(f"sbitfrob:{BitFrobMode(mode).name}")

    def _exec_sshufb(self, dec):
        # 2-Op-permb: src1 = Daten (eine Quelle), src2 = Lane-Vektor = Control.
        # Gruppe via sub&1 (0=s, 1=c).
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        from pipeline import permb
        a = self.read_c(dec['src1']) if dec['sub'] & 1 else self.read_s(dec['src1'])
        b = self.read_c(dec['src2']) if dec['sub'] & 1 else self.read_s(dec['src2'])
        if mode == 0:  # Byte-Permutation: src2 = Index-Vektor (Control)
            out = permb(a, a, b, 0, False, 0, self.flags,
                        blank_enable=bool(ctrl & 0x80))
        elif mode == 1:  # Nibble-Modus
            out = permb(a, a, b, 0, False, 0, self.flags, mode_nibble=True)
        elif mode == 2:  # Shift-Right: src2 = Shift-Menge 0..31
            out = permb(a, a, b, 0, False, 0, self.flags,
                        shift_ctrl=True, shift_left=False)
        elif mode == 3:  # Shift-Left
            out = permb(a, a, b, 0, False, 0, self.flags,
                        shift_ctrl=True, shift_left=True)
        else:
            raise NotImplementedError(f"sshufb-Mode {mode} noch nicht in Shell (Iteration 1)")
        self.write_dst(dec['dst'], out['res'])
        self._count(f"sshufb:{mode}")

    def _exec_cbitfrob(self, dec):
        """F2C cbitfrob_i (C-Gruppe): mode5=(imm>>8)&0x1F, amt=(imm&0xFF)&0x1F.
        Shifts 0..31: eine Passage (permb-Byte-Grob + bitfrob-Fein laufen
        in DERSELBEN Pipeline-Passage — Stufen sind in Reihe, Decoder steuert
        beide gleichzeitig). Kein Zyklus-Zuschlag fuer grosse Shifts; cycle
        zaehlt nur echte Mehrfach-Passagen (Microcode-Loops), nicht die
        Stufen-Durchlaeufe einer Op.
        Hinweis SHR_STICKY: Sticky sammelt nur die Fein-Bits (s2 des Fine-
        Pass); die 8B Byte-Bits gehen in-Shell verloren (HW: Sticky-Kette).
        Grob-Pass-Ops (pipeline.py-Semantik): shift_ctrl nutzt nur src2
        (idx>=4 blankt -> logische Shifts). ROR/ROL brauchen einen Roh-
        Index-Vektor auf dem (a,a)-Funnel (ROR(8k)); ROL via ROR-Komplement
        ROL(A)=ROR(32-A), da shift_ctrl-LSL blankt statt wrap. ASR: Grob
        logisch + Fein Sign-Stacking (s1=Sign, s2 top-8B Sign-OR)."""
        from pipeline import bitfrob, permb
        imm = dec['imm']
        mode = (imm >> 8) & 0x1F
        amt = (imm & 0xFF) & 0x1F
        a = self.read_c(dec['src1'])
        wf = bool(dec['wf'])
        if mode not in SHIFT_FAM:
            out = bitfrob(a, 0, amt, mode, self.flags, write_flags=wf)
            if wf:
                self.flags = out['flags']
            self.write_dst(dec['dst'], out['res'])
            self._count(f"cbitfrob:{BitFrobMode(mode).name}")
            return
        if amt < 8:  # 1 Passage: direkt fein
            if mode in (BitFrobMode.LSR, BitFrobMode.SHR_STICKY):
                s1, s2 = 0, a
            elif mode == BitFrobMode.LSL:
                s1, s2 = a, 0
            elif mode == BitFrobMode.ASR:
                s1 = 0xFFFFFFFF if (a & 0x80000000) else 0
                s2 = a
            else:  # ROR/ROL: Funnel s1||s1
                s1, s2 = a, 0
            out = bitfrob(s1, s2, amt, mode, self.flags, write_flags=wf)
            if wf:
                self.flags = out['flags']
            self.write_dst(dec['dst'], out['res'])
            self._count(f"cbitfrob:{BitFrobMode(mode).name}")
            return
        # 2 Passagen: permb Byte-Grob (coarse) + bitfrob Fein.
        if mode == BitFrobMode.ROL:   # ROL(A) = ROR(32-A)
            two_amt = 32 - amt
            pass_mode = BitFrobMode.ROR
        else:
            two_amt = amt
            pass_mode = mode
        coarse_bytes = two_amt >> 3
        fine = two_amt & 7
        if mode in (BitFrobMode.ROR, BitFrobMode.ROL):
            # Byte-Rot via (a,a)-Funnel + Roh-Index-Vektor [k..k+3]:
            # shift_ctrl blankt idx>=4 (nur 1-Byte-Wrap), LSL blankt i<k;
            # Roh-Vektor = voller 8-Byte-Funnels-Zugriff = ROR(8k) exakt.
            vec = (coarse_bytes + 0) | ((coarse_bytes + 1) << 8) \
                | ((coarse_bytes + 2) << 16) | ((coarse_bytes + 3) << 24)
            out = permb(a, a, vec, 0, False, 0, self.flags, blank_enable=False)
        else:
            # LSR/LSL/SHR_STICKY/ASR-Grob: shift_ctrl, Daten in src2 (Low);
            # shift_ctrl-LSR blankt idx>=4 -> top-Bytes 0 (logischer Shift).
            out = permb(0, a, two_amt, 0, False, 0, self.flags,
                        shift_ctrl=True, shift_left=(mode == BitFrobMode.LSL))
        c1 = out['res']
        if pass_mode in (BitFrobMode.LSR, BitFrobMode.SHR_STICKY):
            f1, f2 = 0, c1
        elif pass_mode == BitFrobMode.LSL:
            f1, f2 = c1, 0
        elif pass_mode == BitFrobMode.ASR:
            # Grob = logisch (top 8B = 0); Fein-ASR kann nur F Bits fuellen.
            # Sign-Stacking: s2 top-8B mit a-Sign OR-en + s1 = Sign-Fill ->
            # Fein-ASR(F) auf asr(a,8B)-Wert = asr(a, 8B+F). (Shell-Operand-
            # Synthese, Zyklus-Modell zaehlt nur Passagen.)
            fill = 0xFFFFFFFF if (a & 0x80000000) else 0
            f1 = fill
            f2 = c1 | (fill & (0xFFFFFFFF << (32 - 8 * coarse_bytes)) & 0xFFFFFFFF)
        else:  # ROR: Funnel s1||s1
            f1, f2 = c1, 0
        out2 = bitfrob(f1, f2, fine, pass_mode, self.flags, write_flags=False)
        self.write_dst(dec['dst'], out2['res'])
        self._count(f"cbitfrob:{BitFrobMode(mode).name}")

    def _exec_ctrl(self, dec):
        scale = 1 << dec['scale_e']
        if dec['wf']:
            # bxx: src1/src2 = Bedingungs-Encoding, Adresse rein PC-relativ
            base = self.pc
            idx = 0
        else:
            base = self.pc if dec['src1'] == 0 else self.read_s(dec['src1'])
            idx = self.read_s(dec['src2']) << scale
        offs = dec['offs'] * 2 * scale
        target = (base + idx + offs) & 0xFFFFFFFF
        taken = False
        if not dec['wf']:  # bra / brl
            if dec['dst'] != 0:
                self.write_dst(dec['dst'], (self.pc + 4) & 0xFFFFFFFF)  # Link
            taken = True
            self._count("brl" if dec['dst'] != 0 else "bra")
            if target == self.pc:  # Selbst-Branch = Halt-Idiom (µC)
                self.halted = True
        else:  # bxx: XOR-Substitution (Lemma R_BCOND_NOW, pipeline_smt.py M24)
            self._count("bxx")
            mask = dec['dst'] & 0xF
            inv = bool(dec['dst'] & 0x10)
            wish = dec['src2'] & 0xF
            p = (dec['src1'] >> 2) & 3
            a, b = _BXX_PAIRS[dec['src1'] & 3]  # 0:S^O 1:C^Z 2:S^Z 3:C^O
            f_eff = self.flags & 0xF
            f_eff = (f_eff & ~(1 << p)) | ((((f_eff >> a) ^ (f_eff >> b)) & 1) << p)
            if inv:
                taken = ((f_eff ^ wish) & mask) == 0
            else:
                taken = ((f_eff ^ wish) & mask) != mask
        if taken:
            self.pc = target
        else:
            self.pc = (self.pc + 4) & 0xFFFFFFFF

    def _exec_mem(self, dec):
        size = 1 << dec['scale_e']
        addr = (self.read_s(dec['src1']) + self.read_s(dec['src2'])
                + dec['offs'] * size) & 0xFFFFFFFF
        if not dec['wf']:  # Load
            self.write_dst(dec['dst'], self.mem_read(addr, size))
            self._count(f"ld.{dec['scale_e']}")
        else:  # Store: dst = Datenquelle
            val = self.read_dst(dec['dst'])
            self.mem_write(addr, size, val)
            self._count(f"st.{dec['scale_e']}")

    def _exec_ldi(self, dec):
        # F-Bit bestimmt Form: 0=MOVX (Halbwort), 1=MASK (Muster).
        # WRF: 0=zero-fill (Rest 0), 1=merge (Rest bleibt).
        dst = dec['dst']
        old = self.read_dst(dst)
        if dec['form'] == 0:  # MOVX
            hw = (dec['imm'] >> 18) & 3
            sext_f = (dec['imm'] >> 16) & 1
            inv_f = (dec['imm'] >> 17) & 1
            v16 = dec['imm'] & 0xFFFF
            if sext_f and (v16 & 0x8000):
                v16 |= 0xFFFF0000
            if inv_f:
                v16 ^= 0xFFFFFFFF
            v = (v16 << (hw * 16)) & 0xFFFFFFFF
            if dec['wf']:  # merge: nur diese Halbwort-Position ersetzen
                mask = 0xFFFF << (hw * 16)
                res = (old & ~mask) | (v & mask)
            else:  # zero-fill: ganze Position + Rest 0
                res = v
        else:  # MASK
            ones = (dec['imm'] >> 15) & 0x1F
            rep = (dec['imm'] >> 12) & 7
            rot = (dec['imm'] >> 7) & 0x1F
            inv_f = (dec['imm'] >> 6) & 1
            elem_bits = {0: 32, 1: 16, 2: 8, 3: 4, 4: 2, 5: 1}.get(rep, 32)
            base = (1 << min(ones, 0 if elem_bits == 0 else 32)) - 1
            # repliziere base ueber das Register, begrenzt auf elem_bits
            elem = base & ((1 << elem_bits) - 1)
            v = 0
            for _i in range(32 // elem_bits):
                v = (v << elem_bits) | elem
            v &= 0xFFFFFFFF
            if rot:
                v = ((v >> rot) | (v << (32 - rot))) & 0xFFFFFFFF
            if inv_f:
                v ^= 0xFFFFFFFF
            if dec['wf']:  # merge: Einsen setzen (OR mit alt), Nullen lassen
                res = old | v
            else:
                res = v
        self.write_dst(dst, res)
        self._count(f"ldi:{'MOVX' if dec['form'] == 0 else 'MASK'}")


    # -- Stepper ------------------------------------------------------------
    def step(self, word, verbose=False):
        dec = self.decode(word)
        if verbose:
            print(f"pc=0x{self.pc:08x} word=0x{word:08x} {dec['plane_entry']}")
        if dec['form'] == 'F3':
            if dec['sem'] == 'carith':
                self._exec_carith(dec)
            elif dec['sem'] == 'ternlog':
                self._exec_ternlog(dec)
            elif dec['sem'] == 'permb':
                self._exec_permb(dec)
            elif dec['sem'] == 'bitfrob':
                self._exec_bitfrob(dec)
            else:
                raise NotImplementedError(f"Plane {dec['sem']} noch nicht in Shell (Iteration 1)")
        elif dec['form'] == 'F2' or dec['form'] == 'F1':
            iname, igroup, _iform = SUBOPS[dec['sub']]
            if iname == 'sarith':
                self._exec_sarith(dec)
            elif iname == 'slogi':
                self._exec_slogi(dec)
            elif iname == 'slogii':
                self._exec_slogii(dec)
            elif iname == 'sbitfrob':
                self._exec_sbitfrob(dec)
            elif iname == 'sshufb':
                self._exec_sshufb(dec)
            else:
                raise NotImplementedError(f"Sub-Op {iname} noch nicht in Shell (Iteration 1)")
        elif dec['sem'] == 'csubsplit':
            self._exec_cbitfrob(dec)
        elif dec['form'] == 'FMEM':
            if dec['sem'] == 'control':
                self._exec_ctrl(dec)
            else:
                self._exec_mem(dec)
        elif dec['sem'] == 'ldi':
            self._exec_ldi(dec)
        self.cycle += 1
        if dec['sem'] not in ('control',):  # Branches setzen pc selbst
            self.pc = (self.pc + 4) & 0xFFFFFFFF

    def run(self, words, start=None, limit=100000, verbose=False):
        if start is not None:
            self.pc = start
        n = 0
        while n < limit and not self.halted:
            pc_off = self.pc
            if pc_off < 0 or pc_off + 4 > len(self.ram):
                raise ValueError(f"PC 0x{self.pc:x} ausserhalb RAM")
            word = int.from_bytes(self.ram[pc_off:pc_off + 4], 'little')
            self.step(word, verbose)
            n += 1
        if n >= limit and not self.halted:
            raise RuntimeError("Instruktions-Limit erreicht (Endlosschleife?)")
        return n

    def load_words(self, addr, words):
        base = addr
        if base < 0 or base + 4 * len(words) > len(self.ram):
            raise ValueError(f"load_words out of range: 0x{addr:x}")
        for i, w in enumerate(words):
            self.ram[base + 4 * i:base + 4 * i + 4] = w.to_bytes(4, 'little')


def _expand_lut2(lut4):
    """2-Input-LUT (4 Funktionen 0..15) -> 3-Input-ternlog-Format:
    ternlog-Index = (a<<2)|(b<<1)|c; c-Eingang tot -> beide c-Varianten gleich."""
    v = 0
    for a in (0, 1):
        for b in (0, 1):
            bit = (lut4 >> ((a << 1) | b)) & 1
            for c in (0, 1):
                if bit:
                    v |= 1 << ((a << 2) | (b << 1) | c)
    return v


# ---------------------------------------------------------------------------
# Smoke-Programm: Summe 1..10 ueber ld/carith/sarith/bxx/bra/st
# Layout: Daten bei 0x1000 (RAM-Offset 0x1000 — RAM flat @0, offset == addr),
# Code bei 0x1080 (load_words).
# Relative Branch-Offsets sind layout-unabhaengig (PC-Basis).
# Imm13 signed reicht nicht fuer RAM-Basen >0xFFF (max 4095) -> 2x Add.
# ---------------------------------------------------------------------------
def build_smoke():
    S1, S2, S3 = 16 + 1, 16 + 2, 16 + 3   # S-Register-Nummern (global 5 Bit)
    C1, C2 = 1, 2
    prog = []
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 0, 1, shift=11))    # S1 = 0x800
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 1, 1, shift=11))    # S1 = 0x1000 (ptr)
    prog.append(sarithi_w(0x8, ArithMode.ADD, S2, 0, 1))       # S2 = 1 (cnt)
    prog.append(sarithi_w(0x8, ArithMode.ADD, S3, 0, 11))      # S3 = 11 (limit)
    prog.append(carith_w(ArithMode.ADD, C1, 0, 0, 0))          # C1 = 0 (sum)
    prog.append(mem_w(C2, 1, 0, 0, 2, wrf=False))              # loop: C2 = ld.w (S1)
    prog.append(carith_w(ArithMode.ADD, C1, 1, C2, 0))         # C1 += C2
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 1, 4))       # S1 += 4
    prog.append(sarithi_w(0x8, ArithMode.ADD, S2, 2, 1))       # S2 += 1
    prog.append(sarith_w(0x0, ArithMode.CMP, 0, 2, 3, wrf=True))  # cmp S2,S3 -> Maske+Flags
    # CMP = Per-Lane-Gleichheits-Maske: res=0 (Z) wenn UNGLEICH, 0xFFFFFFFF (S) wenn gleich
    prog.append(bxx_w(FLAG_S, FLAG_S, chan=1, pair=0, offs=4))  # bxx S -> exit (PC-Basis)
    prog.append(ctrl_w(0, 0, 0, -12, scale=0, wrf=False))      # bra loop (auf ld.w)
    prog.append(mem_w(C1, 1, 0, 0, 2, wrf=True))               # exit: st.w C1 -> (S1)
    prog.append(ctrl_w(0, 0, 0, 0, scale=0, wrf=False))        # bra . (halt)
    return prog


def run_smoke():
    cpu = ShellCPU()
    # Daten: 10 Worte 1..10 bei Adresse 0x1000 (RAM-Offset 0x1000, flat)
    for i in range(10):
        cpu.ram[0x1000 + 4 * i:0x1004 + 4 * i] = (i + 1).to_bytes(4, 'little')
    prog = build_smoke()
    cpu.load_words(0x1080, prog)
    n = cpu.run(prog, start=0x1080)
    print(f"instruktionen: {n}, cycle: {cpu.cycle}")
    print(f"op-counts: {dict(sorted(cpu.op_counts.items()))}")
    print(f"C1 (Summe 1..10): {cpu.read_dst(1)}  (erwartet 55)")
    print(f"RAM[0x1028] (st.w Ergebnis): {int.from_bytes(cpu.ram[0x1028:0x102C], 'little')}")
    print(f"Flags: 0x{cpu.flags:x}  PC: 0x{cpu.pc:x}")
    ok = (cpu.read_dst(1) == 55
          and int.from_bytes(cpu.ram[0x1028:0x102C], 'little') == 55
          and cpu.flags & FLAG_S)
    print("SMOKE:", "PASS" if ok else "FAIL")
    return ok


if __name__ == '__main__':
    ok = run_smoke()
    import sys
    sys.exit(0 if ok else 1)


def check_bxx_wrappers():
    """14 ARM-condition convenience wrappers over bxx_w (XOR-substitution model, see isa_vision.md §3 / M24)."""
    import sys as _sys

    def _bxx_eval(flags, mask, wish, chan, pair, inv):
        """XOR-substitution condition evaluation (replicates _exec_ctrl bxx logic)."""
        p = chan
        a, b = _BXX_PAIRS[pair]
        f_eff = flags & 0xF
        f_eff = (f_eff & ~(1 << p)) | ((((f_eff >> a) ^ (f_eff >> b)) & 1) << p)
        if inv:
            return ((f_eff ^ wish) & mask) == 0
        else:
            return ((f_eff ^ wish) & mask) != mask

    # (name, mask, wish, chan, pair, inv, expected_fn)
    # expected_fn(flags) -> bool where flags = S(bit0)|C(bit1)|Z(bit2)|O(bit3)
    specs = [
        ('bxx_eq', 0x04, 0x04, 0, 0, True,
         lambda f: bool((f >> 2) & 1)),                                       # Z==1
        ('bxx_ne', 0x04, 0x00, 0, 0, True,
         lambda f: not bool((f >> 2) & 1)),                                   # Z==0
        ('bxx_cs', 0x02, 0x02, 0, 0, True,
         lambda f: bool((f >> 1) & 1)),                                       # C==1
        ('bxx_cc', 0x02, 0x00, 0, 0, True,
         lambda f: not bool((f >> 1) & 1)),                                   # C==0
        ('bxx_mi', 0x01, 0x01, 2, 0, True,
         lambda f: bool((f >> 0) & 1)),                                       # S==1
        ('bxx_pl', 0x01, 0x00, 2, 0, True,
         lambda f: not bool((f >> 0) & 1)),                                   # S==0
        ('bxx_vs', 0x08, 0x08, 0, 0, True,
         lambda f: bool((f >> 3) & 1)),                                       # O==1
        ('bxx_vc', 0x08, 0x00, 0, 0, True,
         lambda f: not bool((f >> 3) & 1)),                                   # O==0
        ('bxx_hi', 0x06, 0x02, 0, 0, True,
         lambda f: bool((f >> 1) & 1) and not bool((f >> 2) & 1)),           # C==1 and Z==0
        ('bxx_ls', 0x06, 0x04, 0, 0, False,
         lambda f: not bool((f >> 1) & 1) or bool((f >> 2) & 1)),            # C==0 or Z==1
        ('bxx_ge', 0x01, 0x00, 0, 0, True,
         lambda f: (f & 1) == ((f >> 3) & 1)),                               # S==O
        ('bxx_lt', 0x01, 0x01, 0, 0, True,
         lambda f: (f & 1) != ((f >> 3) & 1)),                               # S!=O
        ('bxx_gt', 0x06, 0x00, 1, 0, True,
         lambda f: (f & 1) == ((f >> 3) & 1) and not bool((f >> 2) & 1)),    # S==O and Z==0
        ('bxx_le', 0x06, 0x0E, 1, 0, False,
         lambda f: (f & 1) != ((f >> 3) & 1) or bool((f >> 2) & 1)),         # S!=O or Z==1
    ]

    for name, mask, wish, chan, pair, inv, exp_fn in specs:
        for flags in range(16):
            actual = _bxx_eval(flags, mask, wish, chan, pair, inv)
            expected = exp_fn(flags)
            if actual != expected:
                s = flags & 1
                c = (flags >> 1) & 1
                z = (flags >> 2) & 1
                o = (flags >> 3) & 1
                print(f"FAIL: {name} flags=S{s}C{c}Z{z}O{o} "
                      f"actual={actual} expected={expected}")
                _sys.exit(1)

    # Negations-Beweis: fuers jede der 14 Spezifikationen muss die Negation
    # (wish ^= mask, inv-Flip) exakt das Komplement feuren, ueber alle 16
    # Flag-Kombis. (XOR-Algebra, hergeleitet aus M24-Semantik.)
    for name, mask, wish, chan, pair, inv, exp_fn in specs:
        for flags in range(16):
            neg_actual = _bxx_eval(flags, mask, wish ^ (mask & 0xF), chan, pair,
                                   not inv)
            if neg_actual == _bxx_eval(flags, mask, wish, chan, pair, inv):
                s = flags & 1
                c = (flags >> 1) & 1
                z = (flags >> 2) & 1
                o = (flags >> 3) & 1
                print(f"FAIL-NEG: {name} flags=S{s}C{c}Z{z}O{o} "
                      f"neg_actual={neg_actual}==original")
                _sys.exit(1)

    print("check_bxx_wrappers: 14/14 OK + 14 Negationen bewiesen")
    return True
