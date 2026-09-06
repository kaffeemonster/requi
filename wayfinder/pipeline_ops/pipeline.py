""" CPU-Pipeline-Simulator: permb -> bitfrob -> ternlog -> arith4 (4 Stufen, 1 Execute-Phase).
    Kernmodul: import-sauber, keine Tests. Kanonischer Testeinstieg: test_pipeline.py
    (python test_pipeline.py [substring] | --list). Helfer: helpers.py, Makro-Op-DSL: ops.py. """
#! /usr/bin/env python

from array import array
from enum import IntEnum

# --- SIMULATOR KERNEL (Die 4 Stufen) ---

MASK_32 = 0xFFFFFFFF
SMASK_32 = 0x80000000

RLEN = 32
MASK_RLEN = (1 << RLEN) - 1
MASK_2RLEN = (1 << RLEN) - 1
FLAG_S = (1 << 0)
FLAG_C = (1 << 1)
FLAG_Z = (1 << 2)
FLAG_O = (1 << 3)
#TODO: Other nice to have flags?

# arith4 Modes (Stufe 4). 0 unbenutzt (res bleibt 0).
# IntEnum: Werte weiterhin int-kompatibel, aber benannt.
class ArithMode(IntEnum):
    ADD       = 1  # s1 + s2 + s3 (Sub via inv_2/inv_3)
    ADDC      = 2  # Add with Carry: res = a+b+s3+c (C aus Flags). inv_2=True -> Subtract-with-
                   #   Borrow (SUBB-Integration): Carry-Beitrag als Borrow c-1, res = a-b-1+c =
                   #   a+~b+c (ARM SBC). C-out = "kein-Borrow" (Addierer-CarryOut der Summe).
                   #   '25' (SUBB) kollabiert hierher; Kern: a + Komplemente + Carry-Slot.
    PADD      = 3  # Packed Add (Lane-Breite via op_type_1: BYTE=8, WORD=16, SCALAR=32)
    SATADD    = 5  # Saturating Add: signed (clamp +-0x7FFFFFFF); unsigned=True = USATADD (clamp 0xFFFFFFFF)
    AVG       = 6  # Rounding Average
    ABSADD    = 7  # |s1| + s2 + s3
    CMP       = 8  # Cmp Mask (0xFF/0xFFFF pro Lane via op_type_1)
    DIV       = 9  # 32x32 Division: res=Quotient(s1/s2), aux=Rest (MULHI-Symmetrie, 0-cost Tap).
                   # bit5=1 unsigned / 0 signed (MUL32-Konvention). s3 ungenutzt.
                   # C-Truncation (KEIN Python-Floor!). div-by-zero DEFINiert: q=0xFFFFFFFF (-1),
                   # rem=s1, FLAG_O. signed Overflow MIN/-1: q=0x80000000, rem=0, FLAG_O.
                   # Flags: S=q-Sign, Z=q==0, O=div-zero|overflow, C nicht abgeleitet.
                   # RISC-V-Modern statt PDP-11/CDC-6000/S-360-Exception. Q117-Q119 (M21)
                   # beweisen 8-bit-Newton-Pfad; Q118/Q119 decken div-zero/rem-Semantik.
    SLT       = 10 # SLT mask: signed (s3=1 -> <, s3=0 -> <=); unsigned=True = SLTU
    # 12 frei (MFC verschoben auf 40)
    MFC       = 40 # INTERN (Marker: Nummer ueber dem 0x1F-Transportbereich = definitiv
                   #   nicht ISA-sichtbar, wie Fenster-Vision 'interne Helper ab 256').
                   #   Carry-Flag -> 0/1 Wert (Mikrocode-Helper, Carry in Register retten).
    ADDSHIFT1 = 13 # s1 + (s2<<1) (lea / *3)
    ADDSHIFT2 = 14 # s1 + (s2<<2) (lea / *5)
    # --- Packed Familie: nur per-Lane Carry-Chain-Taps, kein neuer Block ---
    # Lane-Breite via op_type_1 (BYTE=8, WORD=16, SCALAR=32). 20 frei.
    PMIN      = 15 # Packed Min (unsigned-Steuersignal: True=unsigned, signed=Default 0; SCALAR -> skalares Min, 1 Schritt)
    PMUL16    = 16 # Packed 16x16-MUL: res = lo(s1)*lo(s2), aux = hi(s1)*hi(s2) — 2 unabhaengige
                   # Produkte, MUL32-Quadranten einzeln herausgefuehrt (kein Addierer-Baum,
                   # nur Output-Mux ~50-100 LUT). unsigned-Steuersignal (True=unsigned).
                   # Nutzen: 32x32-Schoolbook (lo/lo+hi/hi parallel), Karatsuba.
    PMAX      = 17 # Packed Max (dito)
    PSADD     = 19 # Packed Saturating Add/Sub: inv_2=True -> lane-correct Sub (INT_MIN-sicher); unsigned-Steuersignal; SCALAR = saturierendes skalar. Add/Sub
    # 21 frei (PSSUB kollabiert in PSADD via inv_2)
    MULFMA    = 22 # FMA hi32 ADD: res = s3 + (s1*s2)>>32. unsigned=True → unsigned (MUL32-
                   # Konvention; bit4 in 16-31 immer gesetzt -> KEIN +/- -Flag, daher
                   # MULFMS=18 fuer die SUB-Variante). aux=lo32 (0-cost Tap, MULHI-Symmetrie).
                   # DSP48E1 A*B+C eingebaut -> ~0 LUT Zusatz auf MUL32-Basis.
                   # Akkumuliert 32x32-Schoolbook-Kreuzterme / MAC im Mikrocode.
    MULFMS    = 18 # FMA hi32 SUB: res = s3 - (s1*s2)>>32. unsigned-Steuersignal (wie MULFMA).
                   # Newton-Iteration r'=2r-b_n*r2hi (M21/M22-Pfad): 1 Pass statt 2.
    PWADD     = 23 # Pairwise Widen-Add: (s1 + (s1>>lb)) & Maske — SWAR-Horizontalsumme, 1 Addierer-Ebene, Shift = feste Verdrahtung (kein Barrel!)
    PSAD      = 24 # PSumAbs SAD: s3 + Summe |lane_i(s1) - lane_i(s2)| (Video-SAD, USADA8-Stil;
                   #   Lane via op_type_1: BYTE=8 Lanes, WORD=4 Lanes, SCALAR=|s1-s2|; s3=Akkumulator)
    # 25 frei (SUBB kollabiert in ADDC via inv_2)
    MUL       = 26 # 16x16->32 unsigned (s1[15:0] * s2[15:0]). DSP/200-300 LUT. Full 32x32 via Mikrocode
    MULADD    = 27 # s3 + (s1[15:0] * s2[15:0]) unsigned. Akkumulator fuer 32x32 Mikrocode
    MUL32     = 28 # 32x32->64. bit5=0=signed, bit5=1=unsigned. res=lo32, aux=hi32. DSP/~500 LUT
    MULHI     = 29 # 32x32 hi32. bit5 selects signed/unsigned. res=obere 32 Bit. Gleicher MUL-Array
    PADD64    = 30 # 64-bit Add (32-bit Lane-Break im Datapfad): s1+s3=lo, s2+aux_in+carry_lo=hi. res=lo, aux=hi. 2. 32-Bit Adder (~64 LUT)
    MUL32ACC  = 31 # 32x32->64 MAC. bit5 selects signed/unsigned. prod=s1*s2, lo=prod_lo+s3, hi=prod_hi+aux+carry. DSP MAC-Kaskade
    SQROM8    = 32 # 8x8->16 via Quadrat-ROM (Elite-1985-Trick): A*B=((A+B)^2-A^2-B^2)>>1.
                   # a=s1&0xFF, b=s2&0xFF. ROM T[n]=n^2, n in [0,510] = 512x18 = 9 Kbit
                   # (1 BlockRAM / ~150 LUT-RAM; Masken-ROM: fast null). ROM-Alternative
                   # zum LUT/DSP-MUL8; 16x16/32x32 via Schoolbook-Mikrocode.

# --- Encoding: orthogonale Signale aus der Nummer extrahiert ---
# mode_imm6 ist ein 6-bit-Transportfeld (Probe-Encoding). Semantisch ist eine
# Op = (Basis-Mode + orthogonale Flag/Helper-Signale); der Dekoder hat breite
# Leitungen. Wo das +/-/-Flag landet (bit5, s3-bit0, separater Leitungs-Slot,
# Fenster ab 32/64/128/256) ist spaetere Mapping-Entscheidung — hier nur die
# benannten Masken, damit die Semantik nicht in magischen Hex-Zahlen steckt.
ARITH4_MODE_MASK = 0x1F   # Basis-Mode aus dem 6-bit mode_imm6
ARITH4_UMODE     = 0x20   # bit5: unsigned-Flag (MUL32-Konvention; 6 Ops:
                          #   MUL32/MULHI/MUL32ACC/MULFMA/MULFMS/DIV)

# bitfrob Modes (Stufe 2). 0..29 belegt.
class BitFrobMode(IntEnum):
    LSR      = 0  # Logical Right Shift (Fine, 0..7)
    LSL      = 1  # Logical Left Shift (Fine)
    ROR      = 2  # Rotate Right (Fine, 0..7; Byte-Vielfache via permb)
    ASR      = 3  # Arithmetic Right Shift (Fine)
    BITREV8  = 4  # Bit-Reverse je Byte (0 LUTs)
    LZC      = 5  # Leading Zero Count
    TZC      = 6  # Trailing Zero Count
    MASK     = 7  # Mask creation: -(s3!=0) all-ones/0
    ROL      = 8  # Rotate Left (Fine, 0..7; Byte-Vielfache via permb)
    SEXT     = 9  # Sign-Extend ab Bit (s3&31)
    POPCNT_N = 10 # Popcount je Nibble (0..4 je Nibble, 4 Bit je Nibble; Teilbaum von POPCNT_B!)
    POPCNT_B = 11 # Popcount je Byte (0..8 je Byte, 4 Bit je Byte; = POPCNT_N + 1 Addierer-Ebene)
    MASKW    = 12 # Mask aus Breite: (1<<n)-1, n = s3&0x1F, n=0 -> 32 (volle Maske). HW: 5->32 Decoder + OR, ~30 LUT
    CLMUL_LO = 13 # CLMUL Byte Low: GF(2)-Mul je Byte-Lane, Low-Byte des 16-Bit-Produkts. AND-Plane + XOR-Tree, ~120 LUT fuer 4 Lanes
    CLMUL_HI = 14 # CLMUL Byte High: dito, Bits [15:8] des 16-Bit-Produkts. ~120 LUT (AND-Plane shared mit LO)
    PARITY_B = 15 # Parity je Byte (4x 8->1 XOR-Trees, ~30 LUT). Result 0x0X0X0X0X, Nibble-Parity via AND 0x11111111
    PARITY_W = 16 # Parity 32-Bit (1x 32->1 XOR-Tree, ~16 LUT). Result in Bit0 (0/1), Halfword-Parity via Byte-Parity XOR
    POLY_RED = 17 # GF(2) Polynom-Reduktion: s1 mod s3 (Poly aus cst/Register). Barrett Shift-XOR, ~50-80 LUT
    BITZIP_8 = 18 # Zero-Interleave lower Byte -> 16 Bit (Morton). SWAR, ~30 LUT. Skalar/Packed via permb
    BITUNZIP_8 = 19 # Compact even Bits lower 16 Bit -> Byte. SWAR, ~30 LUT. Inverse von BITZIP_8
    GFNI_AFFINE = 20 # AES Affine (5-Bit sliding window XOR + const s3). 8x XOR-Baum, ~40 LUT — billiger als ternlog!
    BITSWAP    = 21 # Butterfly: ((x&mask)>>shift) | ((x&~mask)<<shift). mask=~s2[31:0] via cst, shift=s3&31. ~50 LUT
    NIBLKP     = 22 # Nibble-Lookup: s1&0xF index in BITFROB_CST, result=low byte. Orthogonale S-Box Primitive. 16+ Lanes via Packed
    BCD_HC     = 23 # BCD Half-Carry je Byte: ((s1&0x0F0F0F0F)+(s2&0x0F0F0F0F))>>4 & 0x01010101. ~20 LUT. Basis fuer DAA/DAS/DCOR
    BMATOR     = 24 # Bit Matrix OR: res = OR_{k: a[k]=1} ROR(b,k). ~230 LUT (ROR-Bank shared mit BMATXOR)
    BMATXOR    = 25 # Bit Matrix XOR: res = XOR_{k: a[k]=1} ROR(b,k). ~30 LUT extra (XOR-Tree sta / OR-Tree)
    BMAT_N_OR  = 26 # BMM je Nibble OR: 4-Bit-ROR-Bank pro Nibble. ~50 LUT. Baustein fuer Full-BMM via Microcode
    BMAT_N_XOR = 27 # BMM je Nibble XOR: XOR-Tree statt OR-Tree. ~10 LUT extra
    LOG2       = 28 # floor(log2(x)) = 31 - LZC(x). 1-pass statt 2c Microcode. ~5 LUT extra (Inverter auf LZC-Ausgang)
    LOG10      = 29 # floor(log10(x)): 9-threshold comparator chain + priority encoder. ~50 LUT. Verilog parameter gate.
    SHR_STICKY = 30 # Feiner LSR (0..7) + Sticky: rausgeschobene Bits -> aux, O-Flag wenn !=0. Fuer Float-Rounding. ~15 LUT
    PEXT_N     = 31 # Pext auf Nibble-Ebene: Nibbles von s1, wo s2-Bit gesetzt, nach unten komprimieren (8x 4-Bit-Mux + Prefix-Popcount, ~50 LUT)
    PDEP_N     = 32 # Pdep auf Nibble-Ebene: s1-Nibbles auf s2-Bit-Positionen verteilen (gleiche HW wie PEXT_N, Richtung umgekehrt, ~50 LUT)

# BMM Microcode: 8x BMAT_N pro Nibble + permb positionieren + ternlog XOR combine = ~10 passes Full-BMM ohne BMATOR-HW
# LOG2/LOG10: Verilog-Parameter-Tor. LOG2=Inverter auf LZC, LOG10=Magic-Mul+Shift. Kommen Float zustatten.

# Operanden-Typ (Decoder-Steuersignal, 2 Bit pro Operand):
# bestimmt die Lane-Breite fuer Packed-Verhalten. Vom Decoder aus der
# Instruction gelesen, durch die Steuerpfade verdrahtet (kein HW-Block,
# nur Leitungen). Konsumiert wird es aktuell von arith4 fuer die Negation.
class OpType(IntEnum):
    SCALAR = 0 # 32-Bit skalar (Standard)
    BYTE   = 1 # 8x8 Bit Lanes
    WORD   = 2 # 4x16 Bit Lanes
    # 3 = reserviert (Nibble?)


# ternlog LUTs (Stufe 3): 8-Bit Wahrheitstabelle, Index (a<<2)|(b<<1)|c.
# Benannte Standard-Bitops; Werte hier NACH Code-Konvention gerechnet
# (ops_survey.md LUTs hatten andere Bit-Reihenfolge — Tests entscheiden!).
class TernLut(IntEnum):
    CLR      = 0x00 # 0 (clear)
    AND      = 0xC0 # a & b  (Idx 6,7)
    OR       = 0xFC # a | b  (alles ausser a=b=0)
    XOR      = 0x3C # a ^ b  (Idx 2,3,4,5)
    NOT      = 0x01 # ~(a|b|c) — NOR3; "~a" nur bei b=c=0 (Idx 0). Alias: NOR3
    ANDNOT   = 0x30 # a & ~b (Idx 4,5)
    ANDNOT_C = 0x50 # a & ~c (Idx 4,6)
    ORC      = 0xF3 # a | ~b (alles ausser a=0,b=1)
    MOV_A    = 0xF0 # a (b,c egal)
    MOV_B    = 0xCC # b (a,c egal)
    MOV_C    = 0xAA # c (a,b egal)
    SELECT_A = 0xE4 # a wenn c sonst b (cmov/min/max-Muster)
    SELECT_B = 0xD8 # b wenn c sonst a
    SET      = 0xFF # alle 1
    MANDN    = 0x6A # (a & b) ^ c — Masked-AND mit XOR-Maske (Baugh-Wooley-Komposition, 1 Pass)
    # --- NOT-Familie (De Morgan-Komplemente) ---
    NOR       = 0x03 # ~(a|b) — NOR (De Morgan: ~a & ~b)
    NAND      = 0x3F # ~(a&b) — NAND (De Morgan: ~a | ~b)
    XNOR      = 0xC3 # ~(a^b) — XNOR (Gleichheitstest)
    # --- 3-Input-Familie (Parity/Majority) ---
    XOR3      = 0x96 # a^b^c — 3-Input-Parity (auch 0x96 in Tests als Magic-Literal)
    XNOR3     = 0x69 # ~(a^b^c)
    NAND3     = 0x7F # ~(a&b&c)
    NOR3      = 0x01 # ~(a|b|c) — identisch zu NOT (IntEnum-Alias)
    MAJ       = 0xE8 # (a&b)|(b&c)|(a&c) — Majority
    MIN       = 0x17 # ~MAJ — Minority
    # --- ANDNOT/ORC-Komplemente ---
    AND_C     = 0xA0 # a & c (b egal)
    IMPLY     = 0xCF # ~a|b — Implikation (a -> b)
    IMPLY_C   = 0xAF # ~a|c
    ORC_C     = 0xF5 # a|~c
    MANDN_INV = 0x95 # ~((a&b)^c) — invertiertes MANDN


def negate_lanes(x, op_type):
    """ Zweierkomplement-Negation. op_type SCALAR -> Python-Signed-Negation.
        op_type BYTE/WORD -> per-Lane (Carry-Kette an Lane-Grenzen aufgetrennt,
        PADD8/PADD16-Formel, ~x + 1 je Lane mit mod lane_max). """
    if op_type == OpType.BYTE:
        a = (~x) & 0x7F7F7F7F
        b = 0x01010101
        t = a + b
        z = (~x) ^ b
        return (t & 0x7F7F7F7F) | ((((z >> 7) ^ (t >> 7)) & 0x01010101) << 7)
    if op_type == OpType.WORD:
        a = (~x) & 0x7FFF7FFF
        b = 0x00010001
        t = a + b
        z = (~x) ^ b
        return (t & 0x7FFF7FFF) | ((((z >> 15) ^ (t >> 15)) & 0x00010001) << 15)
    return (-x) & MASK_RLEN  # 32-bit-Zweierkomplement-Wrap (signed-negativ wuerde Python-Vergleiche/Shifts verfaelschen)


# Look into imm.md for ideas about more built-in constants


# 16 Magische Konstanten fuer permb
# NON FINAL!! if better masks specific to PERMB operands things can be reshuffled
# first 16 user/compiler visible
PERMB_CST = array('Q', [
    0x0001020304050607, # Identity (little-endian byte order)
    0x0706050403020100, # BSwap 64 (byte-reverse)
    0x0302010007060504, # BSwap 32 (word swap)
    0x0100030205040706, # BSwap 16 (halfword swap)
    0x0000000000000000, # Broadcast Byte 0
    0x0101010101010101, # Broadcast Byte 1
    0x0707070707070707, # Broadcast Byte 7
    0x8080808080808080, # Blank all (mit blank_enable -> 0)
    0x8080808000010203, # Low Word extrahieren (high bytes blank)
    0x0001020380808080, # High Word extrahieren (low bytes blank)
    0x0302010003020100, # Low Word replizieren
    0x0706050407060504, # High Word replizieren
    0x0703060205010400, # Byte Interleave (0,4,1,5,2,6,3,7)
    0x0705030106040200, # Byte De-Interleave (0,2,4,6,1,3,5,7)
    0x0605040302010007, # Byte Rotate Left 1 (ROL 8)
          0x0001000100010001, # 16-Bit Broadcast (bytes 0,1 pair)
    # --- Decoder-only extended entries (index 16..31, ISA unsichtbar) ---
    # 16: identity (redundant, Platzhalter)
    ] + [0] * 16)  # total 32 entries; Decoder kann beliebig viele adressieren

# Nibble-Mode Tabelle (mode_nibble=True + cst_table=True). Low 32 Bit pro Eintrag
# = 8 Nibble-Indizes (je 4 Bit, 0..15 = alle 16 Concat-Nibbles). Kein Blank-Bit:
# Blanking macht ternlog (mask_mode / AND). Optimiert fuer Nibble-Synergien:
# NIBLKP (GF(2^4)-Lookup), BCD, 16-Bit-Lanes, Byte-Halbs-Nibble-Trennung.
PERMB_NIB_CST = array('Q', [
    0x0000000076543210, # Identity: out[n]=concat[n]  (src2 low nibbles)
    0x0000000001234567, # Nibble-Reverse 32 (spiegeln im 32-Bit-Wort)
    0x0000000000000000, # Broadcast Nibble 0
    0x0000000077777777, # Broadcast Nibble 7 (src2 top nibble)
    0x00000000FFFFFFFF, # Broadcast Nibble 15 (src1 top nibble)
    0x0000000032107654, # 16-Bit-Lanes tauschen (4,5,6,7,0,1,2,3)
    0x0000000067452301, # Low/High-Nibble je Byte tauschen
    0x0000000007654321, # Nibble-ROL um 1 (1,2,3,4,5,6,7,0)
    0x0000000065432107, # Nibble-ROR um 1 (7,0,1,2,3,4,5,6)
    0x00000000ECA86420, # Low-Nibbles aller 8 Bytes (0,2,4,..,14) -> NIBLKP-Prep
    0x00000000FDB97531, # High-Nibbles aller 8 Bytes (1,3,5,..,15)
    0x00000000B3A29180, # Zip src1/src2 Nibbles (0,8,1,9,2,10,3,11)
    0x0000000089ABCDEF, # Nibble-Reverse 64 (15..8, src1 spiegeln)
    0x000000003210BA98, # 16-Bit-Lane-Swap ueber src1/src2 (8,9,10,11,0,1,2,3)
    0x0000000076547654, # Byte 2 duplizieren (4,5,6,7,4,5,6,7)
    0x0000000010765432, # Nibble-ROL um 2 (2,3,4,5,6,7,0,1)
    ] + [0] * 16)  # total 32 entries; Decoder erweitert beliebig

# Permb Escape-Vektoren fuer Schiebe-Operationen >= 8 Bit (cst_table=False).
# Decoder synthetisiert diese als Immediate, kein PERMB_CST-Eintrag noetig.
# concat = (src1<<32)|src2; src1=0, src2=x -> concat Bytes [x0..x3, 0,0,0,0].
# LSR um N Bytes: concat[N..N+3] -> Result.
# LSL um N Bytes: concat[4-N..7-N] gepadded mit Nullen -> Result.
PERMB_SHIFT_VEC = {
    'LSR8':  0x04030201,  # concat[1,2,3,4] -> x>>8
    'LSR16': 0x05040302,  # concat[2,3,4,5] -> x>>16
    'LSR24': 0x06050403,  # concat[3,4,5,6] -> x>>24
    'LSL8':  0x02010004,  # concat[4,0,1,2] -> x<<8
    'LSL16': 0x01000404,  # concat[4,4,0,1] -> x<<16
    'LSL24': 0x00040404,  # concat[4,4,4,0] -> x<<24
}

def permb(src1, src2, src3, src3_idx, cst_table, imm6, flags_in, mode_nibble=False, blank_enable=True, prev_in=0, prev_in_strobe=0,  write_flags=False, read_flags=False, internal_table=False, aux_in=0, aux_strobe=0, shift_ctrl=False, shift_left=False):
    """
    src1, src2: Datenquellen (werden zu concat = [src1 | src2] gefuegt)
    src3: Control-Vector mit den Indizes
    cst_table: src3-field was not a register number but an idx in our magic constant table
    mode_nibble: False = Byte-Modus (4 Einheiten), True = Nibble-Modus (8 Einheiten, KEIN Blank)
    Nibble: 4-Bit-Index je Output, waehlt aus allen 16 Concat-Nibbles (0..7=src2, 8..15=src1)
    blank_enable: High-Bit im Index erzeugt 0x00 / 0x0
    shift_ctrl: AltiVec-lvsr-artig — src3 ist Shift-Menge (0..31), permb synthetisiert
        die Byte-Verschiebe-Maske on-the-fly (Byte-Teil = n>>3). Bitfrob macht den Feinteil (n&7).
        shifted_out (rausgeschobene Bytes) -> aux + FLAG_O (Sticky).
    shift_left: Richtung fuer shift_ctrl (False=LSR, True=LSL)
    imm6: ungenutzte bits in der instruction, mehr flags oder modes?
    """

#TODO: Maybe this can be simplyfied? Only inject on one position?
# More degrees of freedom are nice, but add HW
# Strobe bits 0-2 select independent operand injection. Multi-operand injection possible if needed.
    if (prev_in_strobe & 1) == 1:
        src1 = prev_in
    if (prev_in_strobe & 2) == 2:
        src2 = prev_in
    if (prev_in_strobe & 4) == 4:
        src3 = prev_in
# Aux-Strobe (2. Pipe-Slot): unabhaengig von prev_in, ueberschreibt bei Konflikten
    if (aux_strobe & 1) == 1:
        src1 = aux_in
    if (aux_strobe & 2) == 2:
        src2 = aux_in
    if (aux_strobe & 4) == 4:
        src3 = aux_in

#TODO: what can we do with readflags? (only for internal control)

#TODO: find uses for imm6. modes? flags?
    # 64-Bit Concatenation: src1 ist 'HIGH', src2 ist 'LOW'
    concat = ((src1 & MASK_RLEN) << RLEN) | (src2 & MASK_RLEN)

#TODO: fill table with the 16 most used usefull cool constants for permb
#TODO: different tables for nibble/byte mode?
#TODO: different tables for clear/non-clear mode?
    if cst_table:
        table_idx = src3_idx  # volle Breite: ISA limitiert auf 4 Bit, Decoder erweitert
        src3 = PERMB_NIB_CST[table_idx] if mode_nibble else PERMB_CST[table_idx]

    # AltiVec-lvsr-artig: Byte-Verschiebe-Maske on-the-fly aus Shift-Menge synthetisieren
    # (Byte-Teil = n>>3; Feinteil n&7 macht bitfrob). shifted_out -> aux + FLAG_O (Sticky).
    shifted_out = 0
    if shift_ctrl:
        k = (src3 & 0x1F) >> 3   # Byte-Anteil der Shift-Menge (0..3)
        new_src3 = 0
        if not shift_left:       # LSR: Output-Byte i = Concat-Byte (k+i), k+i>=4 -> blank (32-Bit-Wert in src2)
            for i in range(4):
                idx = k + i
                new_src3 |= ((0x80 if idx >= 4 else idx) << (i * 8))
            # rausgeschobene Bytes = Concat-Bytes 0..k-1
            for j in range(min(k, 4)):
                shifted_out |= (concat >> (j * 8)) & 0xFF
        else:                    # LSL: Output-Byte i = Concat-Byte (i-k), i<k -> blank
            for i in range(4):
                idx = i - k
                new_src3 |= ((0x80 if idx < 0 else idx) << (i * 8))
            # rausgeschobene Bytes = Concat-Bytes (8-k)..7
            for j in range(min(k, 4)):
                shifted_out |= (concat >> ((8 - k + j) * 8)) & 0xFF
        src3 = new_src3

    res = 0
    blanked = False  # O-Flag: irgendein Blank-Event passiert?

    if not mode_nibble:
        # === BYTE-MODUS (4 Bytes Output) ===
        # Pro Byte brauchen wir 3 Bit Index (0..7 fuer 8 Bytes in concat) + 1 High-Bit fuer Blank
        for i in range(4):
            ctrl_byte = (src3 >> (i * 8)) & 0xFF
            index = ctrl_byte & 0x07       # 8 moegliche Bytes in concat
            blank = (ctrl_byte & 0x80) != 0 # High-Bit (0x80) -> Blank out

            if blank_enable and blank:
                val = 0x00
                blanked = True
            else:
                val = (concat >> (index * 8)) & 0xFF

            res |= (val << (i * 8))
    else:
        # === NIBBLE-MODUS (8 Nibbles Output, KEIN Blank) ===
        # Volle 4-Bit-Index: jedes Output-Nibble waehlt aus allen 16 Concat-Nibbles
        # (0..7 = src2, 8..15 = src1). Blanking nicht noetig: ternlog mask_mode/AND macht das.
        for i in range(8):
            index = (src3 >> (i * 4)) & 0x0F
            res |= (((concat >> (index * 4)) & 0x0F) << (i * 4))

    flags = 0
    if write_flags:
        flags = flags if ((res & SMASK_32) == 0) else flags | FLAG_S
        flags = flags if not res == 0 else flags | FLAG_Z
        if blanked or shifted_out:
            flags |= FLAG_O  # Blank-Event ODER Shift-Sticky: mind. 1 Byte geleert/rausgeschoben
    else:
        flags = flags_in

#TODO: Bypass is nice, but do we need it? is it usefull?
# this way one stage can only create flags, or we do not have to sweet so much
# where to inject prev_in for a nop in the end the same:
# More degrees of freedom are nice, but adds HW
#TODO: also Bypass flags?
    real_res = 0
    if (prev_in_strobe & 8) == 8:
        real_res = prev_in
    else:
        real_res = res

    r_list = {'res': real_res & MASK_RLEN, 'flags': flags, 'aux': (shifted_out if shift_ctrl else src3) & MASK_RLEN }
    return r_list


# 16 Magische Konstanten fuer Bit-Friemler
# NON FINAL!! if better masks specific to BITFROB operands things can be reshuffled
# first 16 user/compiler visible
BITFROB_CST = array('Q', [
    0x5555555555555555, # Alternative 1/0 Bitmaske (01010101...) $\rightarrow$ BitZip / POPCOUNT Step 1
    0x3333333333333333, # Dual-Bit Maske (00110011...) $\rightarrow$ BitZip / POPCOUNT Step 2
    0x0F0F0F0F0F0F0F0F, # Nibble Maske (00001111...) $\rightarrow$ POPCOUNT Step 3 / BCD-Adjust
    0x00FF00FF00FF00FF, # Byte Maske $\rightarrow$ SIMD 16-Bit Swap / Interleave
    0x0000FFFF0000FFFF, # Word Maske $\rightarrow$ SIMD 32-Bit Swap
    0x0101010101010101, # SWAR Multiplikator $\rightarrow$ Byte-Popcount Summe / String Search
    0x8080808080808080, # High-Bits aller Bytes $\rightarrow$ Gather Sign Bits / ASCII Check
    0x7F7F7F7F7F7F7F7F, # Low-7-Bits aller Bytes $\rightarrow$ ASCII Mask / Saturation Helper
    0x0123456789ABCDEF, # Nibble Index Constant $\rightarrow$ BMM / Shufbitmb Base
    0x8000000000000000, # Sign-Bit 64-Bit MSB
    0x7FFFFFFFFFFFFFFF, # Max Signed Integer 64-Bit
    0xAAAAAAAAAAAAAAAA, # Invertierte Alt-Maske (10101010...)
    0x0303030303030303, # 2-Bit Field Mask
    0x00000000FFFFFFFF, # Low 32-Bit Mask (Zero Extend Word)
    0xFEFEFEFEFEFEFEFE, # PA-RISC / Bit-Hack Magic (Parallel Sub/Add overflow check)
    0xFFFFFFFFFFFFFFFF  # All Ones (wichtig für Invert/Masken-Generierung)
    # --- Decoder-only extended (16..31): Krypto-Polynome, GF-Reduktion ---
] + [
    0x000000000000011B,  # 16: AES GF(2^8) poly x^8+x^4+x^3+x+1
    0x0000000000000013,  # 17: GF(2^4) poly x^4+x+1 (S-box composite field)
    0x000000000000001B,  # 18: x^4+x^3+x+1 (alt GF(2^4) poly)
    0x0000000000000107,  # 19: CRC-8 poly x^8+x^2+x+1
    0x0000000010210482,  # 20: CRC-32 poly (reversed)
    0x000000000000011D,  # 21: Camellia GF(2^8) poly x^8+x^4+x^3+x^2+1
    0x000000000000001D,  # 22: SM4 GF(2^8) poly
] + [0] * (32 - 23) + [
    # GF(2^4) inverse table (NIBLKP, Poly 0x13): entry = inverse nibble at low byte
    0x0000000000000000,  # 32: 0->0
    0x0000000000000001,  # 33: 1->1
    0x0000000000000009,  # 34: 2->9
    0x000000000000000E,  # 35: 3->E=14
    0x000000000000000D,  # 36: 4->D=13
    0x000000000000000B,  # 37: 5->B=11
    0x0000000000000007,  # 38: 6->7
    0x0000000000000006,  # 39: 7->6
    0x000000000000000F,  # 40: 8->F=15
    0x0000000000000002,  # 41: 9->2
    0x000000000000000C,  # 42: A=10->C=12
    0x0000000000000005,  # 43: B=11->5
    0x000000000000000A,  # 44: C=12->A=10
    0x0000000000000004,  # 45: D=13->4
    0x0000000000000003,  # 46: E=14->3
    0x0000000000000008,  # 47: F=15->8
])  # total 48 entries; Decoder kann beliebig viele adressieren

def bitfrob(src1, src2, src3, mode_imm6, flags_in, inv_1=False, inv_2=False, inv_3=False, prev_in=0, prev_in_strobe=0, src3_idx=0, cst_table=False, write_flags=False, read_flags=False, internal_table=False, aux_in=0, aux_strobe=0):
    """ Stufe 2: Bit-Frob (Shifts, Ror, Maskierungen) """

#TODO: Maybe this can be simplyfied? Only inject on one position?
# More degrees of freedom are nice, but add HW
# Strobe bits 0-2 select independent operand injection. Multi-operand injection possible if needed.
    if (prev_in_strobe & 1) == 1:
        src1 = prev_in
    if (prev_in_strobe & 2) == 2:
        src2 = prev_in
    if (prev_in_strobe & 4) == 4:
        src3 = prev_in
# Aux-Strobe (2. Pipe-Slot): unabhaengig von prev_in, ueberschreibt bei Konflikten
    if (aux_strobe & 1) == 1:
        src1 = aux_in
    if (aux_strobe & 2) == 2:
        src2 = aux_in
    if (aux_strobe & 4) == 4:
        src3 = aux_in

#TODO: what can we do with readflags? (only for internal control, on world facing op it is write flags only)
# e.g. change shift direction based on carry? mainly for interal use or can interresting modes created?

#TODO: find more uses for mode_imm6 or add flags?

#TODO: more internal flags where to inject constant?
    if cst_table:
        table_idx = src3_idx  # volle Breite: ISA limitiert auf 4 Bit, Decoder erweitert
        s3 = ~BITFROB_CST[table_idx] if inv_3 else BITFROB_CST[table_idx]
    else:
        s3 = (~src3 & MASK_RLEN) if inv_3 else (src3 & MASK_RLEN)

    # 1. Invertierung der Eingänge
    s1 = (~src1 & MASK_RLEN) if inv_1 else (src1 & MASK_RLEN)
    s2 = (~src2 & MASK_RLEN) if inv_2 else (src2 & MASK_RLEN)

    # 2. Concat fuer Funnel Shift (src1 = HIGH, src2 = LOW)
    concat = (s1 << RLEN) | s2

#TODO: permb helping on shifts/rotate (smaller shifter), good idea or not
    # full 64 bit barrelshifter is expensive
    # but perm can be given "multitasking" (e.g. bswap and rol at same time) masks
    # ROR/ROL hier nur 0..7 Bit (kurzer Barrel, wie LSR/LSL fine).
    # Byte-Vielfache (8/16/24 Bit) macht permb als Byte-Shuffle:
    #   16 Tabellen-Consts ODER Decoder-Escape-Hatch (cst_table=False,
    #   src3 = Index-Vektor direkt aus Decoder, nicht auf 16 limitiert!)
    # Feiner Shift-Betrag (0..7 Bits, da permb die Bytes ausrichtet!)
    shift_amt = s3 & 0x7
    aux_maskw = s1

    # --- MODE SELECTION ---
    res = 0
    sticky_out = 0
    if mode_imm6 == BitFrobMode.LSR:   # Logical Right Shift (Fine)
        res = (concat >> shift_amt) & (MASK_2RLEN >> shift_amt)
    elif mode_imm6 == BitFrobMode.SHR_STICKY: # Feiner LSR + Sticky fuer Float-Rounding
        res = (concat >> shift_amt) & (MASK_2RLEN >> shift_amt)
        sticky_out = (s2 & ((1 << shift_amt) - 1)) if shift_amt else 0  # rausgeschobene Bits (Low-Seite)
    elif mode_imm6 == BitFrobMode.LSL: # Logical Left Shift (Fine)
        res = (concat << shift_amt) >> RLEN
    elif mode_imm6 == BitFrobMode.ROR: # Rotate Right (kurzer Barrel wie LSR, 0..7 Bit; Byte-Vielfache via permb)
        amt = s3 & 0x7
        concat_ror = (s1 << RLEN) | s1
        res = (concat_ror >> amt) & MASK_RLEN
    elif mode_imm6 == BitFrobMode.ASR: # Arithmetic Right Shift (Fine)
        # Sign extension ueber s1
        res = (concat >> shift_amt) & MASK_RLEN
    elif mode_imm6 == BitFrobMode.BITREV8: # Bit-Reverse 8 (In-Byte Reversal, 0 LUTs in HW!)
        for byte_i in range(8):
            b = (s1 >> (byte_i * 8)) & 0xFF
            # Bit-Swap 8-Bit
            b_rev = int('{:08b}'.format(b)[::-1], 2)
            res |= (b_rev << (byte_i * 8))
    elif mode_imm6 == BitFrobMode.LZC: # LZC Block (ETH Zurich Model)
        # Liefert Leading Zero Count von s1
        res = RLEN - (s1 & MASK_RLEN).bit_length() if s1 != 0 else RLEN
    elif mode_imm6 == BitFrobMode.TZC: # TZC Block (ETH Zurich Model)
        # Liefert Trailing Zero Count von s1
        res = (s1 & -s1).bit_length() - 1 if s1 != 0 else RLEN
    elif mode_imm6 == BitFrobMode.MASK: # Mask creation: -(s3!=0) -> all-ones if s3!=0 else 0
        res = MASK_RLEN if s3 != 0 else 0
    elif mode_imm6 == BitFrobMode.MASKW: # Mask aus Breite: (1<<n)-1, n=s3&0x1F; n=0 -> 32 Bit volle Maske
        n = s3 & 0x1F
        res = MASK_RLEN if n == 0 else (1 << n) - 1
        aux_maskw = s3 & MASK_RLEN  # Aux traegt den Breiten-Parameter (0-cost Tap)
    elif mode_imm6 == BitFrobMode.CLMUL_LO: # CLMUL Byte Low: GF(2)-Mul je Lane, Low-Byte. AND-Plane + XOR-Tree, ~120 LUT (4 Lanes)
        for lane in range(4):
            a = (s1 >> (lane * 8)) & 0xFF
            b = (s2 >> (lane * 8)) & 0xFF
            r = 0
            for k in range(8):
                bit = 0
                for i in range(max(0, k - 7), min(k, 7) + 1):
                    bit ^= ((a >> i) & 1) & ((b >> (k - i)) & 1)
                r |= bit << k
            res |= (r & 0xFF) << (lane * 8)
    elif mode_imm6 == BitFrobMode.CLMUL_HI: # CLMUL Byte High: Bits [15:8] des 16-Bit-Produkts je Lane. AND-Plane shared mit LO
        for lane in range(4):
            a = (s1 >> (lane * 8)) & 0xFF
            b = (s2 >> (lane * 8)) & 0xFF
            r = 0
            for k in range(8, 16):
                bit = 0
                for i in range(max(0, k - 7), min(k, 7) + 1):
                    bit ^= ((a >> i) & 1) & ((b >> (k - i)) & 1)
                r |= bit << (k - 8)
            res |= (r & 0xFF) << (lane * 8)
    elif mode_imm6 == BitFrobMode.PARITY_B: # Parity je Byte (4x 8->1 XOR-Trees, ~30 LUT)
        for lane in range(4):
            b = (s1 >> (lane * 8)) & 0xFF
            p = b ^ (b >> 4); p ^= (p >> 2); p ^= (p >> 1); p &= 1
            res |= p << (lane * 8)
    elif mode_imm6 == BitFrobMode.PARITY_W: # Parity 32-Bit (1x 32->1 XOR-Tree, ~16 LUT)
        x = s1 & MASK_RLEN
        x ^= x >> 16; x ^= x >> 8; x ^= x >> 4; x ^= x >> 2; x ^= x >> 1
        res = x & 1
    elif mode_imm6 == BitFrobMode.POLY_RED: # GF(2) Reduktion: s1 mod s3 (Barrett Shift-XOR, HW: Fester XOR-Tree ~50-80 LUT)
        # s3 = Polynom (z.B. AES: 0x11B = x^8 + x^4 + x^3 + x + 1, degree=8)
        val = s1 & MASK_RLEN
        poly = s3 & MASK_RLEN
        poly_degree = poly.bit_length() - 1  # highest set bit = degree
        if poly_degree > 0:
            for i in range(RLEN - 1, poly_degree - 1, -1):
                if val & (1 << i):
                    val ^= poly << (i - poly_degree)
        res = val & MASK_RLEN  # Result in lower poly_degree bits
    elif mode_imm6 == BitFrobMode.BITZIP_8: # Zero-Interleave unteres Byte -> 16 Bit (Morton, ~30 LUT)
        x = s1 & 0xFF
        x = (x | (x << 4)) & 0x0F0F
        x = (x | (x << 2)) & 0x3333
        x = (x | (x << 1)) & 0x5555
        res = x & 0xFFFF
    elif mode_imm6 == BitFrobMode.BITUNZIP_8: # Compact even Bits unterer 16 Bit -> Byte (inverse BITZIP_8, ~30 LUT)
        x = s1 & 0x5555  # keep even-position bits
        x = (x | (x >> 1)) & 0x3333
        x = (x | (x >> 2)) & 0x0F0F
        x = (x | (x >> 4)) & 0x00FF
        res = x & 0xFF
    elif mode_imm6 == BitFrobMode.GFNI_AFFINE: # AES Affine: 5-Bit rotiertes XOR-Fenster + const s3 (~40 LUT)
        x = s1 & 0xFF
        const = s3 & 0xFF
        # AES affine matrix = 0x1F (00011111) rotated by (i+4) per output bit i
        # ROL(0x1F, (i+4)&7): row masks = [0xF1, 0xE3, 0xC7, 0x8F, 0x1F, 0x3E, 0x7C, 0xF8]
        res = 0
        for i in range(8):
            shift = (i + 4) & 7
            m = ((0x1F << shift) | (0x1F >> (8 - shift))) & 0xFF if shift else 0x1F
            v = x & m
            p = v ^ (v >> 4); p ^= (p >> 2); p ^= (p >> 1); p &= 1  # XOR-reduce (no bin().count() hack)
            p ^= (const >> i) & 1
            res |= p << i
    elif mode_imm6 == BitFrobMode.BITSWAP: # Butterfly XOR-Swap: t=((x^(x>>shift))&mask); x^=t^(t<<shift). mask=s2, shift=s3&31 (~50 LUT)
        mask = s2 & MASK_RLEN
        shift_amt = s3 & (RLEN - 1)
        t = ((s1 ^ (s1 >> shift_amt)) & mask) & MASK_RLEN
        res = (s1 ^ t ^ (t << shift_amt)) & MASK_RLEN
    elif mode_imm6 == BitFrobMode.NIBLKP: # Nibble-Lookup: s1&0xF als Index in BITFROB_CST, Low-Byte=Ergebnis. Orthogonale S-Box-Primitive.
        idx = s1 & 0xF
        val = BITFROB_CST[idx + 32]  # GF(2^4) inverse table at entries 32..47
        res = val & 0xFF
    elif mode_imm6 == BitFrobMode.BCD_HC: # BCD Half-Carry je Byte: detect nibble-4 carry
        x = (s1 & 0x0F0F0F0F) + (s2 & 0x0F0F0F0F)
        res = (x >> 4) & 0x01010101  # bit0 je Byte = half-carry
    elif mode_imm6 == BitFrobMode.BMATOR: # Bit Matrix OR: res = OR_{k: a[k]=1} ROR(b,k). 32x32 Crossbar+OR-Tree, ~230 LUT
        res = 0
        mask = s1 & MASK_RLEN
        while mask:
            k = (mask & -mask).bit_length() - 1  # TZC fuer HW: priority encoder
            ror_val = ((s2 << (RLEN - k)) | (s2 >> k)) & MASK_RLEN
            res |= ror_val
            mask &= mask - 1  # clear lowest set bit
    elif mode_imm6 == BitFrobMode.BMATXOR: # Bit Matrix XOR: res = XOR_{k: a[k]=1} ROR(b,k). XOR-Tree statt OR-Tree, ~30 LUT extra
        res = 0
        mask = s1 & MASK_RLEN
        while mask:
            k = (mask & -mask).bit_length() - 1
            ror_val = ((s2 << (RLEN - k)) | (s2 >> k)) & MASK_RLEN
            res ^= ror_val
            mask &= mask - 1
    elif mode_imm6 in (BitFrobMode.BMAT_N_OR, BitFrobMode.BMAT_N_XOR): # BMM Nibble: 4-Bit ROR pro Nibble, 8 parallel (~50 LUT, Baustein)
        is_xor = (mode_imm6 == BitFrobMode.BMAT_N_XOR)
        res = 0
        for i in range(8):  # 8 nibbles in 32 bits
            a_nib = (s1 >> (i*4)) & 0xF
            b_nib = (s2 >> (i*4)) & 0xF
            acc = 0
            for k in range(4):
                if a_nib & (1 << k):
                    r4 = ((b_nib << (4 - k)) | (b_nib >> k)) & 0xF
                    acc = (acc ^ r4) if is_xor else (acc | r4)
            res |= acc << (i*4)  # accumulate into nibble position
        res &= MASK_RLEN
    elif mode_imm6 == BitFrobMode.LOG2: # floor(log2(x)) = 31 - LZC(x). 1-pass, ~5 LUT extra auf LZC
        x = s1 & MASK_RLEN
        lzc = RLEN if x == 0 else (RLEN - x.bit_length())
        res = (RLEN - 1 - lzc) & MASK_RLEN
    elif mode_imm6 == BitFrobMode.LOG10: # floor(log10(x)): table of powers-of-10 comparators + priority encoder. ~50 LUT
        x = s1 & MASK_RLEN
        res = 0
        if x >= 1000000000: res = 9
        elif x >= 100000000: res = 8
        elif x >= 10000000: res = 7
        elif x >= 1000000: res = 6
        elif x >= 100000: res = 5
        elif x >= 10000: res = 4
        elif x >= 1000: res = 3
        elif x >= 100: res = 2
        elif x >= 10: res = 1
        else: res = 0
    elif mode_imm6 == BitFrobMode.PEXT_N: # Pext Nibble: komprimiere Nibbles von s1 laut s2-Bitmaske (8 Bit)
        x = s1 & MASK_RLEN
        m = s2 & 0xFF
        res = 0
        out = 0
        for i in range(8):
            if m & (1 << i):
                res |= ((x >> (i*4)) & 0xF) << (out*4)
                out += 1
    elif mode_imm6 == BitFrobMode.PDEP_N: # Pdep Nibble: verteile s1-Nibbles auf s2-Bit-Positionen (8 Bit)
        x = s1 & MASK_RLEN
        m = s2 & 0xFF
        res = 0
        src = 0
        for i in range(8):
            if m & (1 << i):
                res |= ((x >> (src*4)) & 0xF) << (i*4)
                src += 1
    elif mode_imm6 == BitFrobMode.ROL: # Rotate Left (kurzer Barrel wie LSL, 0..7 Bit; Byte-Vielfache via permb)
        amt = s3 & 0x7
        concat_rol = (s1 << RLEN) | s1
        res = (concat_rol << amt) >> RLEN
    elif mode_imm6 == BitFrobMode.SEXT: # SEXT: s1 ab Bit (s3&31) vorzeichen-erweitern (RISC-V signextend, ~2 Mux-Ebenen)
        pos = s3 & (RLEN - 1)
        low = s1 & ((1 << (pos + 1)) - 1)
        res = (low | (MASK_RLEN & ~((1 << (pos + 1)) - 1))) if (s1 & (1 << pos)) else low
    elif mode_imm6 == BitFrobMode.POPCNT_N: # Popcount je Nibble (SWAR, 2 Ebenen Halb-/Volladdierer; N-Baum ist Teil des B-Baums)
        x = s1 & MASK_RLEN
        x = x - ((x >> 1) & 0x55555555)                     # je 2-Bit-Gruppe: Anzahl gesetzter Bits (0..2)
        x = (x & 0x33333333) + ((x >> 2) & 0x33333333)      # je Nibble: 0..4 (passt in 3 Bit)
        res = x & MASK_RLEN
    elif mode_imm6 == BitFrobMode.POPCNT_B: # Popcount je Byte (POPCNT_N + 1 Addierer-Ebene je Byte-Paar)
        x = s1 & MASK_RLEN
        x = x - ((x >> 1) & 0x55555555)
        x = (x & 0x33333333) + ((x >> 2) & 0x33333333)
        x = (x + (x >> 4)) & 0x0F0F0F0F                     # je Byte: 0..8 (4 Bit)
        res = x
    # MORE
    # what is cheap and helpfull
    #
    # example: ternlog 64 bit only needed 68 LUT, POR-Cuircit 70 LUT,
    # so a ternlog is cheap. if it helps we place another on the inputs (only feed by internal imm8).
    # Then we have one above and below bitfrob

# What of this needs hw (so better help for other stages for other ops, or this
# stage does not need so much help from other stages to not block them), or what
# already is a pseudo op, what can be build all stages cooperating, maybe a little
# bit of microcode (microsequenzing), or can be a "hidden" helper for other ops
# used in microcode (e.g. for floating point of other complex ops)
# DONE-Checkliste (Stand: Kategorie C/G abgeschlossen):
# [x] clz->LZC(5), ctz->TZC(6); cto/clo offen (Microcode: Maske + POPCNT)
# [x] bitrev.8 -> BITREV8(4); volles Bitrev = BITREV8 + permb Nibble-Reorder
# [x] bitzip.8/unzip.8 -> BITZIP_8(18)/BITUNZIP_8(19); Skalar: permb positioniert Bytes, Packed 2x8->16 via BITZIP_8+BITZIP_8HI(permb)
# [x] other blends: BITZIP_8(18)/BITUNZIP_8(19) Morton, BMATOR(24)/BMATXOR(25) crossbar
# [x] popcnt-step -> POPCNT_N(10)/POPCNT_B(11); voller Popcnt = 3 Schritte (POPCNT_B + PWADD + PWADD)
#  ISA delivers popcnt.b (Mode 11) und voller popcnt (Microcode) -> DONE
# [x] mask creations -> MASK(7, !=0) + MASKW(12, (1<<n)-1); mask_mode im ternlog (width=src3_idx, 0=32) befreit bitfrob fuer Shift/ROL -> BFI/UBFX 1-Pass; boxcar (laufende 1en) offen
# "Bit Twiddling Hacks" Sean Eron Anderson (Stanford)
# "Hacker's Delight" von Henry S. Warren.
# [x] GFNI carryless multiply: CLMUL_LO(13)/CLMUL_HI(14) packed byte; full 32b CLMUL = Mikrocode (permb Shuffle + CLMUL_B + ternlog XOR, ~10-15 Schritte)
#    CRC32 Barrett-Reduction = 3x CLMUL + 1x XOR; braucht 64b CLMUL = Macro-Mikrocode ueber Register-File
# [~] ptest/test-under-mask: Microcode (ternlog AND + CMP + Flags)
# [~] Booth-Mikroschritt: 2-Pass (Pass1=MASK(MplierBit) + Pass2=LSL+mask_mode+ADD); CTZ-MUL = schneller (sparsam, 8-Bit Demo getestet)
# [x] BMM (Bit Matrix Multiply): BMATOR(24)/BMATXOR(25) 32x32 crossbar+OR/XOR-tree ~260 LUT. BMAT_N_OR(26)/BMAT_N_XOR(27) per-nibble 4-bit ROR ~60 LUT (BMM in 8 nibble-passes). Synthesizer sees reuse with BITREV8/BITSWAP.
#TODO: shufbitmb, compress/expand, TBM (Bit-Shuffle-HW, teuer)
# [~] gather/scatter Sign-Bits: permb Nibble + Shift, kein Direkt-Mode
# [x] parity: PARITY_B(15)/PARITY_W(16); Nibble-Parity via ternlog AND 0x11111111; Halfword via Byte-Parity XOR (~30 LUT Byte, ~16 LUT Word)
# [~] pext/pdep/cfuged/BDEPG/BEXTG: verschoben (andere Runde); BFI/BFC/SBFX/UBFX -> TODO C (Writeback)
# [x] 8x8 bit transpose (vgbbd): BITSWAP 3-stage butterfly demo, TEST 25
#TODO: strategic BCD acceleration: [x] BCD_HC(23) Half-Carry je Byte. DAA/DAS/DCOR = 4-Pass Mikrocode. [~] PA-RISC UXOR/ldi/uaddcm/dcor via ternlog+arith4.
# [x] integer multiply: MUL(26) 16x16->32, MULADD(27), MUL32(28) 32x32->64 signed, MULHI(29). 32x32 unsigned = Mikrocode via MUL(26).
# [x] binary-to-gray + gray-to-binary: Microcode (shift+ternlog XOR; LSR fine + permb escape fuer Breit-Shifts; getestet mit 0x12345678/0xDEADBEEF)
# [x] rotate then (and/xor/or/insert): 2-Schritt-Microcode (bitfrob ROL/ROR + ternlog), Kategorie C
#TODO: parisc uxor/ldi, uaddcm dcor
# [~] ALPHA suite: ZAPNOT = permb blank + ternlog; EXTR* = SEXT+SHR; CMPGEB = CMP + Flags
# [~] bit test/set/clear: Microcode (MASKW + ternlog AND/OR/ANDNOT), kein Direkt-Mode
# [x] RISCV suite: SEXT(9), MASKW(12)=zeroextend, PMIN/PMAX=min/max; orc.b offen (CMP-0 + NOT + OR)
#TODO: All masked set, any set (masked) and back to masks
# [x] LOG2(28) 31-LZC 1-pass (~5 LUT), LOG10(29) 9-comparator chain 1-pass (~50 LUT). roundup pow2: Microcode (LZC+LSL+mask).
#TODO: ((soft-)float helper)

# [x] arm64-style imm creation -> imm_encode(val, width=32): zero/maskw/replicate/signext/permb/synthesize, 16 smoke tests

#[x] Packed versions -> arith4: PADD/CMP/PMIN/PMAX/PSADD/PWADD/PSAD (Lane via op_type)

    flags = 0
    if write_flags:
        flags = flags if ((res & SMASK_32) == 0) else flags | FLAG_S
        flags = flags if not res == 0 else flags | FLAG_Z
        if sticky_out:
            flags |= FLAG_O  # Shift-Sticky: Bits rausgeschoben (Float-Rounding)
    else:
        flags = flags_in

#TODO: Bypass is nice, but do we need it? is it usefull?
# this way one stage can only create flags, or we do not have to sweet so much
# where to inject prev_in for a nop, in the end the same:
# More degrees of freedom are nice, but adds HW
#TODO: also Bypass flags?
    real_res = 0
    if (prev_in_strobe & 8) == 8:
        real_res = prev_in
    else:
        real_res = res

    r_list = {'res': real_res & MASK_RLEN, 'flags': flags, 'aux': (sticky_out if mode_imm6 == BitFrobMode.SHR_STICKY else (aux_maskw if mode_imm6 == BitFrobMode.MASKW else s1)) & MASK_RLEN }
    return r_list


# 16 Magische Konstanten fuer ternlog
# NON FINAL!! if better masks specific to TERNLOG operands things can be reshuffled
# first 16 user/compiler visible
TERNLOG_CST = array('Q', [
    0x0000000000000000, # Zero (a|b durch LUT, oder clear)
    0xFFFFFFFFFFFFFFFF, # All Ones (NOT / force)
    0x5555555555555555, # Alternating (bitzip / parity mix)
    0xAAAAAAAAAAAAAAAA, # Invert Alternating
    0x0F0F0F0F0F0F0F0F, # Nibble Maske
    0xF0F0F0F0F0F0F0F0, # Invert Nibble Maske
    0x00FF00FF00FF00FF, # Byte Maske (even bytes)
    0xFF00FF00FF00FF00, # Byte Maske (odd bytes)
    0x0000FFFF0000FFFF, # Word Maske (even words)
    0xFFFF0000FFFF0000, # Word Maske (odd words)
    0x00000000FFFFFFFF, # Low 32 Maske
    0xFFFFFFFF00000000, # High 32 Maske
    0x8080808080808080, # High-Bit pro Byte
    0x7F7F7F7F7F7F7F7F, # Low-7-Bits pro Byte
    0x0101010101010101, # SWAR Broadcast / Add-Maske
    0x3333333333333333, # 2-Bit Field Maske
    # --- Decoder-only extended (16..31): AES/GFNI affine constants, crypto patterns ---
] + [
     0x0000000000000063,  # 16: AES S-box affine XOR constant
     0x000000000000000F,  # 17: Nibble mask (Galois Field op helper)
     0x00FF00FF00FF00FF,  # 18: Byte mask (duplicate, safer extended copy)
     0x0F0F0F0F0F0F0F0F,  # 19: Nibble mask (duplicate)
     0x001F001F001F001F,  # 20: GF(2^5) mask
] + [0] * (32 - 21) + [
    # --- AES S-Box ROM (32..287): 256-byte lookup via ternlog MOV_C + cst_table ---
    # 1 BRAM18k block. TernLut.MOV_C (0xAA) + cst_table=True + src3_idx=32+byte
    # = 1-pass S-box. Decoder can also slice/rotate for other S-box layers.
    0x6363636363636363,  # 32: S(0x00)=0x63
    0x7C7C7C7C7C7C7C7C,  # 33: S(0x01)=0x7C
    0x7777777777777777,  # 34: S(0x02)=0x77
    0x7B7B7B7B7B7B7B7B,  # 35: S(0x03)=0x7B
    0xF2F2F2F2F2F2F2F2,  # 36: S(0x04)=0xF2
    0x6B6B6B6B6B6B6B6B,  # 37: S(0x05)=0x6B
    0x6F6F6F6F6F6F6F6F,  # 38: S(0x06)=0x6F
    0xC5C5C5C5C5C5C5C5,  # 39: S(0x07)=0xC5
    0x3030303030303030,  # 40: S(0x08)=0x30
    0x0101010101010101,  # 41: S(0x09)=0x01
    0x6767676767676767,  # 42: S(0x0A)=0x67
    0x2B2B2B2B2B2B2B2B,  # 43: S(0x0B)=0x2B
    0xFEFEFEFEFEFEFEFE,  # 44: S(0x0C)=0xFE
    0xD7D7D7D7D7D7D7D7,  # 45: S(0x0D)=0xD7
    0xABABABABABABABAB,  # 46: S(0x0E)=0xAB
    0x7676767676767676,  # 47: S(0x0F)=0x76
    0xCACACACACACACACA,  # 48: S(0x10)=0xCA
    0x8282828282828282,  # 49: S(0x11)=0x82
    0xC9C9C9C9C9C9C9C9,  # 50: S(0x12)=0xC9
    0x7D7D7D7D7D7D7D7D,  # 51: S(0x13)=0x7D
    0xFAFAFAFAFAFAFAFA,  # 52: S(0x14)=0xFA
    0x5959595959595959,  # 53: S(0x15)=0x59
    0x4747474747474747,  # 54: S(0x16)=0x47
    0xF0F0F0F0F0F0F0F0,  # 55: S(0x17)=0xF0
    0xADADADADADADADAD,  # 56: S(0x18)=0xAD
    0xD4D4D4D4D4D4D4D4,  # 57: S(0x19)=0xD4
    0xA2A2A2A2A2A2A2A2,  # 58: S(0x1A)=0xA2
    0xAFAFAFAFAFAFAFAF,  # 59: S(0x1B)=0xAF
    0x9C9C9C9C9C9C9C9C,  # 60: S(0x1C)=0x9C
    0xA4A4A4A4A4A4A4A4,  # 61: S(0x1D)=0xA4
    0x7272727272727272,  # 62: S(0x1E)=0x72
    0xC0C0C0C0C0C0C0C0,  # 63: S(0x1F)=0xC0
    0xB7B7B7B7B7B7B7B7,  # 64: S(0x20)=0xB7
    0xFDFDFDFDFDFDFDFD,  # 65: S(0x21)=0xFD
    0x9393939393939393,  # 66: S(0x22)=0x93
    0x2626262626262626,  # 67: S(0x23)=0x26
    0x3636363636363636,  # 68: S(0x24)=0x36
    0x3F3F3F3F3F3F3F3F,  # 69: S(0x25)=0x3F
    0xF7F7F7F7F7F7F7F7,  # 70: S(0x26)=0xF7
    0xCCCCCCCCCCCCCCCC,  # 71: S(0x27)=0xCC
    0x3434343434343434,  # 72: S(0x28)=0x34
    0xA5A5A5A5A5A5A5A5,  # 73: S(0x29)=0xA5
    0xE5E5E5E5E5E5E5E5,  # 74: S(0x2A)=0xE5
    0xF1F1F1F1F1F1F1F1,  # 75: S(0x2B)=0xF1
    0x7171717171717171,  # 76: S(0x2C)=0x71
    0xD8D8D8D8D8D8D8D8,  # 77: S(0x2D)=0xD8
    0x3131313131313131,  # 78: S(0x2E)=0x31
    0x1515151515151515,  # 79: S(0x2F)=0x15
    0x0404040404040404,  # 80: S(0x30)=0x04
    0xC7C7C7C7C7C7C7C7,  # 81: S(0x31)=0xC7
    0x2323232323232323,  # 82: S(0x32)=0x23
    0xC3C3C3C3C3C3C3C3,  # 83: S(0x33)=0xC3
    0x1818181818181818,  # 84: S(0x34)=0x18
    0x9696969696969696,  # 85: S(0x35)=0x96
    0x0505050505050505,  # 86: S(0x36)=0x05
    0x9A9A9A9A9A9A9A9A,  # 87: S(0x37)=0x9A
    0x0707070707070707,  # 88: S(0x38)=0x07
    0x1212121212121212,  # 89: S(0x39)=0x12
    0x8080808080808080,  # 90: S(0x3A)=0x80
    0xE2E2E2E2E2E2E2E2,  # 91: S(0x3B)=0xE2
    0xEBEBEBEBEBEBEBEB,  # 92: S(0x3C)=0xEB
    0x2727272727272727,  # 93: S(0x3D)=0x27
    0xB2B2B2B2B2B2B2B2,  # 94: S(0x3E)=0xB2
    0x7575757575757575,  # 95: S(0x3F)=0x75
    0x0909090909090909,  # 96: S(0x40)=0x09
    0x8383838383838383,  # 97: S(0x41)=0x83
    0x2C2C2C2C2C2C2C2C,  # 98: S(0x42)=0x2C
    0x1A1A1A1A1A1A1A1A,  # 99: S(0x43)=0x1A
    0x1B1B1B1B1B1B1B1B,  # 100: S(0x44)=0x1B
    0x6E6E6E6E6E6E6E6E,  # 101: S(0x45)=0x6E
    0x5A5A5A5A5A5A5A5A,  # 102: S(0x46)=0x5A
    0xA0A0A0A0A0A0A0A0,  # 103: S(0x47)=0xA0
    0x5252525252525252,  # 104: S(0x48)=0x52
    0x3B3B3B3B3B3B3B3B,  # 105: S(0x49)=0x3B
    0xD6D6D6D6D6D6D6D6,  # 106: S(0x4A)=0xD6
    0xB3B3B3B3B3B3B3B3,  # 107: S(0x4B)=0xB3
    0x2929292929292929,  # 108: S(0x4C)=0x29
    0xE3E3E3E3E3E3E3E3,  # 109: S(0x4D)=0xE3
    0x2F2F2F2F2F2F2F2F,  # 110: S(0x4E)=0x2F
    0x8484848484848484,  # 111: S(0x4F)=0x84
    0x5353535353535353,  # 112: S(0x50)=0x53
    0xD1D1D1D1D1D1D1D1,  # 113: S(0x51)=0xD1
    0x0000000000000000,  # 114: S(0x52)=0x00
    0xEDEDEDEDEDEDEDED,  # 115: S(0x53)=0xED
    0x2020202020202020,  # 116: S(0x54)=0x20
    0xFCFCFCFCFCFCFCFC,  # 117: S(0x55)=0xFC
    0xB1B1B1B1B1B1B1B1,  # 118: S(0x56)=0xB1
    0x5B5B5B5B5B5B5B5B,  # 119: S(0x57)=0x5B
    0x6A6A6A6A6A6A6A6A,  # 120: S(0x58)=0x6A
    0xCBCBCBCBCBCBCBCB,  # 121: S(0x59)=0xCB
    0xBEBEBEBEBEBEBEBE,  # 122: S(0x5A)=0xBE
    0x3939393939393939,  # 123: S(0x5B)=0x39
    0x4A4A4A4A4A4A4A4A,  # 124: S(0x5C)=0x4A
    0x4C4C4C4C4C4C4C4C,  # 125: S(0x5D)=0x4C
    0x5858585858585858,  # 126: S(0x5E)=0x58
    0xCFCFCFCFCFCFCFCF,  # 127: S(0x5F)=0xCF
    0xD0D0D0D0D0D0D0D0,  # 128: S(0x60)=0xD0
    0xEFEFEFEFEFEFEFEF,  # 129: S(0x61)=0xEF
    0xAAAAAAAAAAAAAAAA,  # 130: S(0x62)=0xAA
    0xFBFBFBFBFBFBFBFB,  # 131: S(0x63)=0xFB
    0x4343434343434343,  # 132: S(0x64)=0x43
    0x4D4D4D4D4D4D4D4D,  # 133: S(0x65)=0x4D
    0x3333333333333333,  # 134: S(0x66)=0x33
    0x8585858585858585,  # 135: S(0x67)=0x85
    0x4545454545454545,  # 136: S(0x68)=0x45
    0xF9F9F9F9F9F9F9F9,  # 137: S(0x69)=0xF9
    0x0202020202020202,  # 138: S(0x6A)=0x02
    0x7F7F7F7F7F7F7F7F,  # 139: S(0x6B)=0x7F
    0x5050505050505050,  # 140: S(0x6C)=0x50
    0x3C3C3C3C3C3C3C3C,  # 141: S(0x6D)=0x3C
    0x9F9F9F9F9F9F9F9F,  # 142: S(0x6E)=0x9F
    0xA8A8A8A8A8A8A8A8,  # 143: S(0x6F)=0xA8
    0x5151515151515151,  # 144: S(0x70)=0x51
    0xA3A3A3A3A3A3A3A3,  # 145: S(0x71)=0xA3
    0x4040404040404040,  # 146: S(0x72)=0x40
    0x8F8F8F8F8F8F8F8F,  # 147: S(0x73)=0x8F
    0x9292929292929292,  # 148: S(0x74)=0x92
    0x9D9D9D9D9D9D9D9D,  # 149: S(0x75)=0x9D
    0x3838383838383838,  # 150: S(0x76)=0x38
    0xF5F5F5F5F5F5F5F5,  # 151: S(0x77)=0xF5
    0xBCBCBCBCBCBCBCBC,  # 152: S(0x78)=0xBC
    0xB6B6B6B6B6B6B6B6,  # 153: S(0x79)=0xB6
    0xDADADADADADADADA,  # 154: S(0x7A)=0xDA
    0x2121212121212121,  # 155: S(0x7B)=0x21
    0x1010101010101010,  # 156: S(0x7C)=0x10
    0xFFFFFFFFFFFFFFFF,  # 157: S(0x7D)=0xFF
    0xF3F3F3F3F3F3F3F3,  # 158: S(0x7E)=0xF3
    0xD2D2D2D2D2D2D2D2,  # 159: S(0x7F)=0xD2
    0xCDCDCDCDCDCDCDCD,  # 160: S(0x80)=0xCD
    0x0C0C0C0C0C0C0C0C,  # 161: S(0x81)=0x0C
    0x1313131313131313,  # 162: S(0x82)=0x13
    0xECECECECECECECEC,  # 163: S(0x83)=0xEC
    0x5F5F5F5F5F5F5F5F,  # 164: S(0x84)=0x5F
    0x9797979797979797,  # 165: S(0x85)=0x97
    0x4444444444444444,  # 166: S(0x86)=0x44
    0x1717171717171717,  # 167: S(0x87)=0x17
    0xC4C4C4C4C4C4C4C4,  # 168: S(0x88)=0xC4
    0xA7A7A7A7A7A7A7A7,  # 169: S(0x89)=0xA7
    0x7E7E7E7E7E7E7E7E,  # 170: S(0x8A)=0x7E
    0x3D3D3D3D3D3D3D3D,  # 171: S(0x8B)=0x3D
    0x6464646464646464,  # 172: S(0x8C)=0x64
    0x5D5D5D5D5D5D5D5D,  # 173: S(0x8D)=0x5D
    0x1919191919191919,  # 174: S(0x8E)=0x19
    0x7373737373737373,  # 175: S(0x8F)=0x73
    0x6060606060606060,  # 176: S(0x90)=0x60
    0x8181818181818181,  # 177: S(0x91)=0x81
    0x4F4F4F4F4F4F4F4F,  # 178: S(0x92)=0x4F
    0xDCDCDCDCDCDCDCDC,  # 179: S(0x93)=0xDC
    0x2222222222222222,  # 180: S(0x94)=0x22
    0x2A2A2A2A2A2A2A2A,  # 181: S(0x95)=0x2A
    0x9090909090909090,  # 182: S(0x96)=0x90
    0x8888888888888888,  # 183: S(0x97)=0x88
    0x4646464646464646,  # 184: S(0x98)=0x46
    0xEEEEEEEEEEEEEEEE,  # 185: S(0x99)=0xEE
    0xB8B8B8B8B8B8B8B8,  # 186: S(0x9A)=0xB8
    0x1414141414141414,  # 187: S(0x9B)=0x14
    0xDEDEDEDEDEDEDEDE,  # 188: S(0x9C)=0xDE
    0x5E5E5E5E5E5E5E5E,  # 189: S(0x9D)=0x5E
    0x0B0B0B0B0B0B0B0B,  # 190: S(0x9E)=0x0B
    0xDBDBDBDBDBDBDBDB,  # 191: S(0x9F)=0xDB
    0xE0E0E0E0E0E0E0E0,  # 192: S(0xA0)=0xE0
    0x3232323232323232,  # 193: S(0xA1)=0x32
    0x3A3A3A3A3A3A3A3A,  # 194: S(0xA2)=0x3A
    0x0A0A0A0A0A0A0A0A,  # 195: S(0xA3)=0x0A
    0x4949494949494949,  # 196: S(0xA4)=0x49
    0x0606060606060606,  # 197: S(0xA5)=0x06
    0x2424242424242424,  # 198: S(0xA6)=0x24
    0x5C5C5C5C5C5C5C5C,  # 199: S(0xA7)=0x5C
    0xC2C2C2C2C2C2C2C2,  # 200: S(0xA8)=0xC2
    0xD3D3D3D3D3D3D3D3,  # 201: S(0xA9)=0xD3
    0xACACACACACACACAC,  # 202: S(0xAA)=0xAC
    0x6262626262626262,  # 203: S(0xAB)=0x62
    0x9191919191919191,  # 204: S(0xAC)=0x91
    0x9595959595959595,  # 205: S(0xAD)=0x95
    0xE4E4E4E4E4E4E4E4,  # 206: S(0xAE)=0xE4
    0x7979797979797979,  # 207: S(0xAF)=0x79
    0xE7E7E7E7E7E7E7E7,  # 208: S(0xB0)=0xE7
    0xC8C8C8C8C8C8C8C8,  # 209: S(0xB1)=0xC8
    0x3737373737373737,  # 210: S(0xB2)=0x37
    0x6D6D6D6D6D6D6D6D,  # 211: S(0xB3)=0x6D
    0x8D8D8D8D8D8D8D8D,  # 212: S(0xB4)=0x8D
    0xD5D5D5D5D5D5D5D5,  # 213: S(0xB5)=0xD5
    0x4E4E4E4E4E4E4E4E,  # 214: S(0xB6)=0x4E
    0xA9A9A9A9A9A9A9A9,  # 215: S(0xB7)=0xA9
    0x6C6C6C6C6C6C6C6C,  # 216: S(0xB8)=0x6C
    0x5656565656565656,  # 217: S(0xB9)=0x56
    0xF4F4F4F4F4F4F4F4,  # 218: S(0xBA)=0xF4
    0xEAEAEAEAEAEAEAEA,  # 219: S(0xBB)=0xEA
    0x6565656565656565,  # 220: S(0xBC)=0x65
    0x7A7A7A7A7A7A7A7A,  # 221: S(0xBD)=0x7A
    0xAEAEAEAEAEAEAEAE,  # 222: S(0xBE)=0xAE
    0x0808080808080808,  # 223: S(0xBF)=0x08
    0xBABABABABABABABA,  # 224: S(0xC0)=0xBA
    0x7878787878787878,  # 225: S(0xC1)=0x78
    0x2525252525252525,  # 226: S(0xC2)=0x25
    0x2E2E2E2E2E2E2E2E,  # 227: S(0xC3)=0x2E
    0x1C1C1C1C1C1C1C1C,  # 228: S(0xC4)=0x1C
    0xA6A6A6A6A6A6A6A6,  # 229: S(0xC5)=0xA6
    0xB4B4B4B4B4B4B4B4,  # 230: S(0xC6)=0xB4
    0xC6C6C6C6C6C6C6C6,  # 231: S(0xC7)=0xC6
    0xE8E8E8E8E8E8E8E8,  # 232: S(0xC8)=0xE8
    0xDDDDDDDDDDDDDDDD,  # 233: S(0xC9)=0xDD
    0x7474747474747474,  # 234: S(0xCA)=0x74
    0x1F1F1F1F1F1F1F1F,  # 235: S(0xCB)=0x1F
    0x4B4B4B4B4B4B4B4B,  # 236: S(0xCC)=0x4B
    0xBDBDBDBDBDBDBDBD,  # 237: S(0xCD)=0xBD
    0x8B8B8B8B8B8B8B8B,  # 238: S(0xCE)=0x8B
    0x8A8A8A8A8A8A8A8A,  # 239: S(0xCF)=0x8A
    0x7070707070707070,  # 240: S(0xD0)=0x70
    0x3E3E3E3E3E3E3E3E,  # 241: S(0xD1)=0x3E
    0xB5B5B5B5B5B5B5B5,  # 242: S(0xD2)=0xB5
    0x6666666666666666,  # 243: S(0xD3)=0x66
    0x4848484848484848,  # 244: S(0xD4)=0x48
    0x0303030303030303,  # 245: S(0xD5)=0x03
    0xF6F6F6F6F6F6F6F6,  # 246: S(0xD6)=0xF6
    0x0E0E0E0E0E0E0E0E,  # 247: S(0xD7)=0x0E
    0x6161616161616161,  # 248: S(0xD8)=0x61
    0x3535353535353535,  # 249: S(0xD9)=0x35
    0x5757575757575757,  # 250: S(0xDA)=0x57
    0xB9B9B9B9B9B9B9B9,  # 251: S(0xDB)=0xB9
    0x8686868686868686,  # 252: S(0xDC)=0x86
    0xC1C1C1C1C1C1C1C1,  # 253: S(0xDD)=0xC1
    0x1D1D1D1D1D1D1D1D,  # 254: S(0xDE)=0x1D
    0x9E9E9E9E9E9E9E9E,  # 255: S(0xDF)=0x9E
    0xE1E1E1E1E1E1E1E1,  # 256: S(0xE0)=0xE1
    0xF8F8F8F8F8F8F8F8,  # 257: S(0xE1)=0xF8
    0x9898989898989898,  # 258: S(0xE2)=0x98
    0x1111111111111111,  # 259: S(0xE3)=0x11
    0x6969696969696969,  # 260: S(0xE4)=0x69
    0xD9D9D9D9D9D9D9D9,  # 261: S(0xE5)=0xD9
    0x8E8E8E8E8E8E8E8E,  # 262: S(0xE6)=0x8E
    0x9494949494949494,  # 263: S(0xE7)=0x94
    0x9B9B9B9B9B9B9B9B,  # 264: S(0xE8)=0x9B
    0x1E1E1E1E1E1E1E1E,  # 265: S(0xE9)=0x1E
    0x8787878787878787,  # 266: S(0xEA)=0x87
    0xE9E9E9E9E9E9E9E9,  # 267: S(0xEB)=0xE9
    0xCECECECECECECECE,  # 268: S(0xEC)=0xCE
    0x5555555555555555,  # 269: S(0xED)=0x55
    0x2828282828282828,  # 270: S(0xEE)=0x28
    0xDFDFDFDFDFDFDFDF,  # 271: S(0xEF)=0xDF
    0x8C8C8C8C8C8C8C8C,  # 272: S(0xF0)=0x8C
    0xA1A1A1A1A1A1A1A1,  # 273: S(0xF1)=0xA1
    0x8989898989898989,  # 274: S(0xF2)=0x89
    0x0D0D0D0D0D0D0D0D,  # 275: S(0xF3)=0x0D
    0xBFBFBFBFBFBFBFBF,  # 276: S(0xF4)=0xBF
    0xE6E6E6E6E6E6E6E6,  # 277: S(0xF5)=0xE6
    0x4242424242424242,  # 278: S(0xF6)=0x42
    0x6868686868686868,  # 279: S(0xF7)=0x68
    0x4141414141414141,  # 280: S(0xF8)=0x41
    0x9999999999999999,  # 281: S(0xF9)=0x99
    0x2D2D2D2D2D2D2D2D,  # 282: S(0xFA)=0x2D
    0x0F0F0F0F0F0F0F0F,  # 283: S(0xFB)=0x0F
    0xB0B0B0B0B0B0B0B0,  # 284: S(0xFC)=0xB0
    0x5454545454545454,  # 285: S(0xFD)=0x54
    0xBBBBBBBBBBBBBBBB,  # 286: S(0xFE)=0xBB
    0x1616161616161616,  # 287: S(0xFF)=0x16
])  # total 288 entries; Decoder kann beliebig viele adressieren

def ternlog(a, b, c, lut_imm8, flags_in, prev_in=0, prev_in_strobe=0, src3_idx=0, cst_table=False, write_flags=False, read_flags=False, internal_table=False, mask_mode=False, aux_in=0, aux_strobe=0):
    """ Stufe 3: Bitweise 3-Input LUT (Ternary Logic). mask_mode: c durch width-Maske ersetzen (width=src3_idx&0x1F, 0=32). Befreit bitfrob fuer Shift etc. """

#TODO: Maybe this can be simplyfied? Only inject on one position?
# More degrees of freedom are nice, but add HW
# Strobe bits 0-2 select independent operand injection. Multi-operand injection possible if needed.
    if (prev_in_strobe & 1) == 1:
        a = prev_in
    if (prev_in_strobe & 2) == 2:
        b = prev_in
    if (prev_in_strobe & 4) == 4:
        c = prev_in
# Aux-Strobe (2. Pipe-Slot): unabhaengig von prev_in, ueberschreibt bei Konflikten
    if (aux_strobe & 1) == 1:
        a = aux_in
    if (aux_strobe & 2) == 2:
        b = aux_in
    if (aux_strobe & 4) == 4:
        c = aux_in
#TODO: what can we do with readflags? (only for internal control, on op it is write flags only)

#TODO: more internal flags where to inject constant?
    if cst_table:
        table_idx = src3_idx  # volle Breite: ISA limitiert auf 4 Bit, Decoder erweitert
        c = TERNLOG_CST[table_idx]

    if mask_mode:
        width = src3_idx & 0x1F
        ms = MASK_RLEN if width == 0 else (1 << width) - 1
        c = ms & MASK_RLEN  # ersetzt c mit width-Maske (cst_table wird ueberschrieben)

    res = 0
    for bit in range(32):
        # Nimm Bit 'bit' aus A, B und C
        bit_a = (a >> bit) & 1
        bit_b = (b >> bit) & 1
        bit_c = (c >> bit) & 1
        # Index in die 8-Bit Wahrheitstabelle (0..7)
        idx = (bit_a << 2) | (bit_b << 1) | bit_c
        # Hole das Ergebnis-Bit aus lut_imm8
        res_bit = (lut_imm8 >> idx) & 1
        res |= (res_bit << bit)

    flags = 0
    if write_flags:
        flags = flags if ((res & SMASK_32) == 0) else flags | FLAG_S
        flags = flags if not res == 0 else flags | FLAG_Z
    else:
        flags = flags_in

#TODO: Bypass is nice, but do we need it? is it usefull?
# this way one stage can only create flags, or we do not have to sweet so much
# where to inject prev_in for a nop, in the end the same:
# More degrees of freedom are nice, but adds HW
#TODO: also Bypass flags?
    real_res = 0
    if (prev_in_strobe & 8) == 8:
        real_res = prev_in
    else:
        real_res = res

    r_list = {'res': real_res & MASK_RLEN, 'flags': flags, 'aux': c & MASK_RLEN }
    return r_list


# 16 Magische Konstanten fuer arith4
# NON FINAL!! if better masks specific to ARITH4 operands things can be reshuffled
# first 16 user/compiler visible
ARITH_CST = array('Q', [
    0x0000000000000000, # Zero (pass-through)
    0x0000000000000001, # Increment by 1
    0xFFFFFFFFFFFFFFFF, # Decrement by 1 (-1)
    0x8000000000000000, # Sign-Bit (flip sign via add)
    0x7FFFFFFFFFFFFFFF, # Max Signed
    0x00000000FFFFFFFF, # Low 32 Maske (zero-extend)
    0xFFFFFFFF00000000, # High 32 Maske
    0x0000000100000000, # Carry into bit 32
    0xAAAAAAAAAAAAAAAB, # Magic /3 (64-Bit)
    0xCCCCCCCCCCCCCCCD, # Magic /5 (64-Bit)
    0x9E3779B97F4A7C15, # Golden Ratio (Knuth hash)
    0xBF58476D1CE4E5B9, # SplitMix64 mix
    0x94D049BB133111EB, # SplitMix64 mix
    0xCBF29CE484222325, # FNV-1a 64-Bit prime
    0x5FE6EB50C7B537A9, # Fast InvSqrt (Double)
    0x3FF0000000000000, # 1.0 double
    # --- Decoder-only extended (16..31): S-box affine, crypto constants ---
] + [
    0x0000000000000063,  # 16: AES S-box affine XOR value
    0x0000000000000080,  # 17: 0x80 Byte-Sign (saturating helper)
    0x0000000000010000,  # 18: carry-into-bit16
    0x0000000100000000,  # 19: carry-into-bit32 (duplicate)
    0x0000000000008000,  # 20: 0x8000 Word-Sign
     0x0000001B0000001B,  # 21: 0x1B per Byte (AES Rcon)
     0x000000000000007F,  # 22: Float-Bias 127 (Single-Precision Exp)
     0x000000003F800000,  # 23: 1.0f (Single)
     0x000000003F000000,  # 24: 0.5f (Single)
     0x000000007F800000,  # 25: +inf (Single)
     0x00000000FF800000,  # 26: -inf (Single)
     0x000000007FC00000,  # 27: NaN (Single)
     0x000000004B000000,  # 28: 2^23 (Single, Normalisierungs-Konstante)
     0x00000000007FFFFF,  # 29: Max-Denormal (Single)
     0x0000000000800000,  # 30: Min-Normal (Single)
     0x0000000000800000,  # 31: Min-Normal (dup, Platzhalter)
])

def arith4(src1, src2, src3, mode_imm6, flags_in, inv_1=False, inv_2=False, inv_3=False, prev_in=0, prev_in_strobe=0, src3_idx=0, cst_table=False, write_flags=False, read_flags=False, internal_table=False, op_type_1=OpType.SCALAR, op_type_2=OpType.SCALAR, op_type_3=OpType.SCALAR, aux_in=0, aux_strobe=0, unsigned=False):
    """ arith4-Auswertung. unsigned = orthogonales Steuersignal (DeDekoder-Leitung,
        NICHT in mode_imm6 gepackt — fuer ops_survey 'Encoding: Mode vs Flags').
        MUL32-Konvention: False=signed, True=unsigned. SLT: True=SLTU. SATADD:
        True=USATADD. """
    """ Stufe 4: Arithmetik & Carry Chain """

#TODO: add switch to use prev_in based on ... mode? hidden flag? insert where?
#TODO: Maybe this can be simplyfied? Only inject on one position?
# More degrees of freedom are nice, but add HW
# Strobe bits 0-2 select independent operand injection. Multi-operand injection possible if needed.
    if (prev_in_strobe & 1) == 1:
        src1 = prev_in
    if (prev_in_strobe & 2) == 2:
        src2 = prev_in
    if (prev_in_strobe & 4) == 4:
        src3 = prev_in
# Aux-Strobe (2. Pipe-Slot): unabhaengig von prev_in, ueberschreibt bei Konflikten
    if (aux_strobe & 1) == 1:
        src1 = aux_in
    if (aux_strobe & 2) == 2:
        src2 = aux_in
    if (aux_strobe & 4) == 4:
        src3 = aux_in
#TODO: what can we do with readflags besides the obvious? only for internal control, on op it is write flags only)

    # 1. Negierung der Eingänge (op_type: skalar oder per-Lane bei Packed-Daten)
    s1 = negate_lanes(src1, op_type_1) if inv_1 else src1
    s2 = negate_lanes(src2, op_type_2) if inv_2 else src2

    if cst_table:
        table_idx = src3_idx  # volle Breite: ISA limitiert auf 4 Bit, Decoder erweitert
        s3 = -ARITH_CST[table_idx] if inv_3 else ARITH_CST[table_idx]  # Konstanten: skalar
    else:
        s3 = negate_lanes(src3, op_type_3) if inv_3 else src3

    res = 0
    aux_cmp = s3  # default: bei CMP-Mode ueberschrieben mit XOR-Diff (per-Lane, 0-cost Tap)
    div_zero_or_ovf = False  # DIV-Dispatch setzt True (div-zero/overflow); hier vorab fuer pyright
    if mode_imm6 == ArithMode.ADD: # Normal Add (Sub = Add mit inv_2/inv_3, kein eigenes SUB noetig)
        res = (s1 + s2 + s3) & MASK_RLEN
    elif mode_imm6 == ArithMode.ADDC: # Add with Carry (Flags). inv_2=True = SUBB-Integration:
        #   b dreht Vorzeichen (negate_lanes, Zeile 1161: -b) und der Carry-Beitrag wird
        #   Borrow (c-1 statt c) -> res = a - b - 1 + c = a + ~b + c (ARM SBC). Der
        #   Addierer-CarryOut dieser Summe IST "kein-Borrow" (a+~b+c >= 2^32  <=> a >=
        #   b+borrow) -> der Flags-Branch braucht C-keinen-Sonderfall. Kern: a + Komp + Slot.
        c_add = (1 if (flags_in & FLAG_C) else 0) - (1 if inv_2 else 0)
        res = (s1 + s2 + s3 + c_add) & MASK_RLEN
    elif mode_imm6 == ArithMode.PADD: # Packed Add: Carry-Kette per Lane aufgetrennt (Lane-Breite via op_type_1)
        lane_bits = 8 if op_type_1 == OpType.BYTE else (16 if op_type_1 == OpType.WORD else 32)
        lm = 0x7F7F7F7F if lane_bits == 8 else (0x7FFF7FFF if lane_bits == 16 else 0x7FFFFFFF)
        gm = 0x01010101 if lane_bits == 8 else (0x00010001 if lane_bits == 16 else 0x00000001)
        t = (s1 & lm) + (s2 & lm)
        x = (s1 ^ s2) & MASK_RLEN
        res = (t & lm) | ((((x >> (lane_bits - 1)) ^ (t >> (lane_bits - 1))) & gm) << (lane_bits - 1))
    elif mode_imm6 == ArithMode.SATADD: # Saturating Add: unsigned=True -> USATADD (clamp 0xFFFFFFFF)
        if unsigned:
            full = s1 + s2 + s3
            res = MASK_RLEN if full > MASK_RLEN else full & MASK_RLEN
        else:  # signed-32-Interpretation: Bit31 -> Wert - 2^32 (auf echter Summe saturieren)
            s1s = s1 - (MASK_RLEN + 1) if s1 & 0x80000000 else s1
            s2s = s2 - (MASK_RLEN + 1) if s2 & 0x80000000 else s2
            s3s = s3 - (MASK_RLEN + 1) if s3 & 0x80000000 else s3
            sm = s1s + s2s + s3s
            res = 0x7FFFFFFF if sm > 0x7FFFFFFF else (0x80000000 if sm < -0x80000000 else sm & MASK_RLEN)
    elif mode_imm6 == ArithMode.AVG: # Rounding Average (s1+s2+round)>>1, round = s3&1
        res = (s1 + s2 + (s3 & 1)) >> 1
    elif mode_imm6 == ArithMode.ABSADD: # Abs-Add |s1| + s2 + s3 (Vorzeichen = Bit31)
        av = s1 & MASK_RLEN
        absa = ((MASK_RLEN - av + 1) & MASK_RLEN) if (av & 0x80000000) else av  # 2^32-av (mod 2^32) bei Bit31
        res = absa + (s2 & MASK_RLEN) + (s3 & MASK_RLEN)
    elif mode_imm6 == ArithMode.CMP: # Cmp Mask: 0xFF/0xFFFF pro Lane wo s1==s2 (per-Lane Zero-Detect, kein Borrow)
        lane_bits = 8 if op_type_1 == OpType.BYTE else (16 if op_type_1 == OpType.WORD else 32)
        lm = 0x7F7F7F7F if lane_bits == 8 else (0x7FFF7FFF if lane_bits == 16 else 0x7FFFFFFF)
        gm = 0x01010101 if lane_bits == 8 else (0x00010001 if lane_bits == 16 else 0x00000001)
        x = (s1 ^ s2) & MASK_RLEN
        aux_cmp = x  # per-Lane XOR-Diff (0-cost Tap, nuetzlich fuer Borrow-Wiederverwendung)
        y = (x & lm) + lm
        z = ~(y | x | lm) & MASK_RLEN
        m = (z >> (lane_bits - 1)) & gm
        res = ((m << lane_bits) - m) & MASK_RLEN
    elif mode_imm6 == ArithMode.SLT: # SLT mask: all-ones wenn s1 < s2 (s3=1) bzw. s1 <= s2 (s3=0)
        # unsigned=True = SLTU: unsigned Vergleich, Carry-Out = kein Borrow (ARM-Style C=1).
        # signed (Default): Sign-Flip-Operanden, dann Unsigned-Borrow (Overflow-sicher, gleiche HW).
        # s3=1 -> a<b, s3=0 -> a<=b. inv_2 bleibt bewusst ignoriert (raw src2), wie bisher.
        if unsigned:
            full = (s1 & MASK_RLEN) + (~(src2 & MASK_RLEN) & MASK_RLEN) + (s3 & MASK_RLEN)
            res = MASK_RLEN if (full >> RLEN) == 0 else 0
        else:
            ca = (s1 & MASK_RLEN) ^ 0x80000000
            cb = (src2 & MASK_RLEN) ^ 0x80000000
            t33 = (ca & MASK_RLEN) + ((~cb) & MASK_RLEN) + (s3 & MASK_RLEN)   # Python, nativer 33-Bit-Carry
            res = MASK_RLEN if (t33 >> 32) == 0 else 0
    elif mode_imm6 == ArithMode.MFC: # MFC (Mode 40, INTERN-Marker): Carry-Flag -> 0/1 Wert.
        # Mikrocode-Helper fuer Carry-Rettung; bewegt sich NICHT in der sichtbaren ISA
        # (dort deckt loadmsr FLAGS, DST das ab). write/read_flags-Kette der Pipeline
        # macht Carry-Rettung in reinen ADDC-Kaskaden ueberfluessig (Zwischen-Ops
        # schreiben schlicht keine Flags); bleibt fuer Carry-als-Datenwert-Faelle.
        res = 1 if (flags_in & FLAG_C) else 0
    elif mode_imm6 == ArithMode.ADDSHIFT1: # AddShifted LSL#1: s1 + (s2<<1) (lea / *3; feste Verdrahtung, 0 Gates)
        res = (s1 + ((s2 & MASK_RLEN) << 1)) & MASK_RLEN
    elif mode_imm6 == ArithMode.ADDSHIFT2: # AddShifted LSL#2: s1 + (s2<<2) (lea / *5; feste Verdrahtung, 0 Gates)
        res = (s1 + ((s2 & MASK_RLEN) << 2)) & MASK_RLEN
    elif mode_imm6 in (ArithMode.PMIN, ArithMode.PMAX): # Min/Max: per-Lane Borrow via Carry-Chain-Taps (Lane-Breite via op_type_1)
        lane_bits = 8 if op_type_1 == OpType.BYTE else (16 if op_type_1 == OpType.WORD else 32)
        lane_max = (1 << lane_bits) - 1
        sign_flip = 1 << (lane_bits - 1)
        signed = not unsigned  # unsigned-Steuersignal (True=unsigned, signed=Default 0); s3 bleibt frei
        is_max = mode_imm6 == ArithMode.PMAX
        for i in range(RLEN // lane_bits):
            av = (s1 >> (i * lane_bits)) & lane_max
            bv = (s2 >> (i * lane_bits)) & lane_max
            ca, cb = av, bv
            if signed:
                ca ^= sign_flip     # Vorzeichen-Bit drehen: signed Vergleich wird unsigned
                cb ^= sign_flip
            a_gt = 1 if (ca + (~cb & lane_max)) > lane_max else 0  # Carry-Out der Lane = a > b
            res |= (bv if (a_gt != is_max) else av) << (i * lane_bits)
    elif mode_imm6 == ArithMode.PSADD: # Saturating Add/Sub: Overflow via Carry-Taps (cin XOR cout; Lane via op_type_1)
        # inv_2=True -> lane-correct Sub (a + ~b + 1 via Taps, NICHT -b-Wrap: INT_MIN-Lane 0x80
        # wuerde auf sich selbst mappen und a-0x80 statt a+0x80 liefern -> falsche Saturation).
        # s1/s2 sind bei inv_1/inv_2 bereits lane-negativ (negate_lanes, Zeile 1161); der
        # sub-Pfad nimmt deshalb raw src2. '21' (PSSUB) kollabiert in diesen Mode.
        lane_bits = 8 if op_type_1 == OpType.BYTE else (16 if op_type_1 == OpType.WORD else 32)
        lane_max = (1 << lane_bits) - 1
        sign_bit = 1 << (lane_bits - 1)
        low_mask = sign_bit - 1
        signed = not unsigned  # unsigned-Steuersignal (True=unsigned, signed=Default 0); s3 bleibt frei
        is_sub = inv_2
        for i in range(RLEN // lane_bits):
            av = (s1 >> (i * lane_bits)) & lane_max
            raw = (src2 if is_sub else s2)
            bv = (raw >> (i * lane_bits)) & lane_max
            be = (~bv) & lane_max if is_sub else bv   # Sub = Add mit Komplement
            carry_into_top = 1 if ((av & low_mask) + (be & low_mask) + (1 if is_sub else 0)) > low_mask else 0
            sfull = av + be + (1 if is_sub else 0)
            carry_out = 1 if sfull > lane_max else 0
            t = sfull & lane_max
            if not signed:
                if is_sub:
                    val = 0 if not carry_out else t        # Borrow -> Clamp 0
                else:
                    val = lane_max if carry_out else t     # Overflow -> Clamp max
            else:
                overflow = carry_into_top ^ carry_out      # signed Overflow: cin XOR cout
                if overflow:
                    val = (sign_bit - 1) if (t & sign_bit) else sign_bit  # Clamp 0x7F / 0x80
                else:
                    val = t
            res |= (val & lane_max) << (i * lane_bits)
    elif mode_imm6 == ArithMode.PWADD: # Pairwise Widen-Add (SWAR-Horizontalsumme). s1 only; s2 nur bei SCALAR.
        # (x + (x >> lb)) & Maske: je Lane-Paar Summe in naechst-groessere Lane.
        # Shift um lb = feste Byte-/Word-Verdrahtung, keine Barrelkosten. Summen mod 2^(2*lb) je Ausgangslane.
        if op_type_1 == OpType.BYTE:
            res = (s1 + (s1 >> 8)) & 0x00FF00FF
        elif op_type_1 == OpType.WORD:
            res = (s1 + (s1 >> 16)) & 0x0000FFFF
        else: # SCALAR: degeneriert zu s1 + s2 (volles Add)
            res = (s1 + s2) & MASK_RLEN
    elif mode_imm6 == ArithMode.PSAD: # PSumAbs SAD: s3 + Summe |lane(s1) - lane(s2)| (Video-SAD; Lane via op_type_1)
        # HW: n x (lb-Bit-Sub mit Borrow-Out) + Select-Mux + (n-1)-Addierer-Reduktionsbaum + 1 Akku-Add.
        # s3 = Akkumulator (SAD in laufende Summe addieren). Q90/Q90w (M17) beweisen
        # BYTE/WORD-Identitaet gegen 9/17-Bit-Vorzeichen-Referenz.
        lane_bits = 8 if op_type_1 == OpType.BYTE else (16 if op_type_1 == OpType.WORD else 32)
        lane_mask = (1 << lane_bits) - 1
        sad = 0
        for i in range(RLEN // lane_bits):
            av = (s1 >> (i * lane_bits)) & lane_mask
            bv = (s2 >> (i * lane_bits)) & lane_mask
            sad += (av - bv) if av >= bv else (bv - av)
        res = (s3 + sad) & MASK_RLEN
    elif mode_imm6 == ArithMode.MUL: # 16x16->32 unsigned
        a = s1 & 0xFFFF
        b = s2 & 0xFFFF
        res = (a * b) & MASK_RLEN
    elif mode_imm6 == ArithMode.MULADD: # s3 + 16x16->32 unsigned akkumulieren
        a = s1 & 0xFFFF
        b = s2 & 0xFFFF
        res = (s3 + a * b) & MASK_RLEN
    elif mode_imm6 == ArithMode.SQROM8: # 8x8->16 via Quadrat-ROM (Elite-Trick)
        # A*B = ((A+B)^2 - A^2 - B^2) >> 1, unsigned 8x8, a=s1&0xFF, b=s2&0xFF.
        # (A+B) in 9 bit (max 510), Quadrat-Diff in 18 bit ((A+B)^2 <= 260100 < 2^18;
        # stets >= A^2+B^2, da Kreuzterm 2AB >= 0 -> nie negativ). res <= 65025.
        # Q115 bewiesen (pipeline_smt.py M20), Fuzzer-verifiziert.
        a = s1 & 0xFF
        b = s2 & 0xFF
        sq = (a + b) * (a + b)
        res = ((sq - a * a - b * b) >> 1) & MASK_RLEN
    elif mode_imm6 == ArithMode.PMUL16: # Packed 16x16-MUL: res=lo*lo, aux=hi*hi
        # 2 unabhaengige 16x16-Produkte parallel (MUL32-Quadranten einzeln
        # herausgefuehrt, kein Addierer-Baum -> nur Output-Mux ~50-100 LUT).
        # unsigned-Steuersignal: True=unsigned, signed=Default 0 (Packed-Konvention). 32x32-Schoolbook:
        # lo/lo + hi/hi in 1 Pass, Kreuzterme via MULFMA/MUL16. s3 bleibt frei.
        signed_p = not unsigned
        if signed_p:
            i1a = (s1 & 0xFFFF) - 0x10000 if (s1 & 0x8000) else (s1 & 0xFFFF)
            i1b = (s1 >> 16) - 0x10000 if (s1 & 0x80000000) else (s1 >> 16)
            i2a = (s2 & 0xFFFF) - 0x10000 if (s2 & 0x8000) else (s2 & 0xFFFF)
            i2b = (s2 >> 16) - 0x10000 if (s2 & 0x80000000) else (s2 >> 16)
            res = (i1a * i2a) & MASK_RLEN
            aux_cmp = (i1b * i2b) & MASK_RLEN
        else:
            res = ((s1 & 0xFFFF) * (s2 & 0xFFFF)) & MASK_RLEN
            aux_cmp = ((s1 >> 16) * (s2 >> 16)) & MASK_RLEN
    elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MUL32: # 32x32->64. bit5=unsigned. res=lo32, aux=hi32
        if unsigned:
            prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)  # 64-bit unsigned
        else:
            i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
            i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
            prod = i1 * i2  # 64-bit signed
        res = prod & MASK_RLEN
        aux_cmp = (prod >> 32) & MASK_RLEN
    elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MULHI: # 32x32 hi32, aux=lo32. bit5=unsigned
        if unsigned:
            prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)  # 64-bit unsigned
        else:
            i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
            i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
            prod = i1 * i2  # 64-bit signed
        res = (prod >> 32) & MASK_RLEN
        aux_cmp = prod & MASK_RLEN  # res=hi32, aux=lo32 (symmetrisch zu MUL32, 0-cost Tap)
    elif mode_imm6 == ArithMode.PADD64: # 64-bit Add (32-bit Lane-Break im Datapfad): s1+s3=lo, s2+aux_in+carry=hi
        lo = (s1 & MASK_RLEN) + (s3 & MASK_RLEN)
        carry_lo = 1 if lo > MASK_RLEN else 0
        hi = (s2 & MASK_RLEN) + (aux_in & MASK_RLEN) + carry_lo
        res = lo & MASK_RLEN
        aux_cmp = hi & MASK_RLEN
    elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MUL32ACC: # 32x32->64 MAC. bit5=unsigned
        if unsigned:
            prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)  # 64-bit unsigned
        else:
            i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
            i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
            prod = i1 * i2  # 64-bit signed
        prod_lo = prod & MASK_RLEN
        prod_hi = (prod >> 32) & MASK_RLEN
        lo = (prod_lo & MASK_RLEN) + (s3 & MASK_RLEN)
        carry_lo = 1 if lo > MASK_RLEN else 0
        hi = (prod_hi & MASK_RLEN) + (aux_in & MASK_RLEN) + carry_lo
        res = lo & MASK_RLEN
        aux_cmp = hi & MASK_RLEN
    elif (mode_imm6 & ARITH4_MODE_MASK) in (ArithMode.MULFMA, ArithMode.MULFMS): # FMA hi32: res = s3 ± (s1*s2)>>32
        # DSP48E1 A*B+C eingebaut -> ~0 LUT Zusatz auf MUL32-Basis (Addierer-Baum
        # speist 3. Operanden statt nur 2-Output). bit5=1 unsigned/0 signed (MUL32-
        # Konvention). MULFMA=ADD s3+hi, MULFMS=SUB s3-hi (bit4 ist in Modes 16-31
        # immer gesetzt -> kein +/- -Flag, zwei Modes statt dessen). aux=lo32 (0-cost
        # Tap). MULFMS: Newton-Iteration r'=2r-b_n*r2hi (M21/M22-32-bit-Pfad) 1 Pass
        # statt 2; MULFMA: Schoolbook-Kreuzterm-/MAC-Akkumulation.
        sub = (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MULFMS
        if unsigned:
            prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)  # 64-bit unsigned
        else:
            i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
            i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
            prod = i1 * i2  # 64-bit signed
        prod_hi = (prod >> 32) & MASK_RLEN
        if sub:
            res = (s3 - prod_hi) & MASK_RLEN
        else:
            res = (s3 + prod_hi) & MASK_RLEN
        aux_cmp = prod & MASK_RLEN
    elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.DIV: # 32x32 Div. bit5=1 unsigned / 0 signed. res=q, aux=rem
        d = src2 & MASK_RLEN
        div_zero_or_ovf = False
        if d == 0:
            # definiert (K2): div-by-zero -> q=0xFFFFFFFF (-1), rem=s1, FLAG_O
            q = 0xFFFFFFFF
            r = src1 & MASK_RLEN
            div_zero_or_ovf = True
        elif unsigned:
            a = src1 & MASK_RLEN
            q = a // d
            r = a % d
        else:
            i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
            i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
            if i1 == -0x80000000 and i2 == -1:
                # signed Overflow: MIN/-1 -> q=0x80000000 (MIN), rem=0, FLAG_O
                q = 0x80000000
                r = 0
                div_zero_or_ovf = True
            else:
                aq = abs(i1) // abs(i2)
                q = -aq if ((i1 < 0) != (i2 < 0)) else aq
                r = i1 - q * i2      # C-Rest: Vorzeichen folgt Dividend (KEIN Python-Floor-%)
                q = q & MASK_RLEN
                r = r & MASK_RLEN
        res = q
        aux_cmp = r
# Packed Sub via op_type: PADD + inv_2 + op_type_2=BYTE/WORD = Per-Lane-Negation
# (wrapping Sub ohne Saturation). PSADD+inv_2 = saturierender Sub (lane-correct Taps,
# INT_MIN-sicher — negate von INT_MIN wuerde auf sich selbst mappen und falsch saturieren).
# Skalares Min/Max: PMIN/PMAX mit op_type_1=SCALAR = 1 Schritt (unsigned-Steuersignal: True=unsigned).
# 2-Schritt-Variante (SLT-Mask + ternlog select) weiterhin moeglich wenn Flags gewuenscht.
# AddShifted = bitfrob shift + add hier.
# Packed Familie direkt: nur per-Lane Carry-Chain-Taps (Borrow/Overflow), Lane-Breite via op_type_1.
    # esp the cheap ones, HW is already there, only needs a bit of opening the
    # carry chain, or looking at some bits (saturated math)
#TODO: output mask modes/ops
    # you get your result and update flags if you want
    # or you can get a mask to do more simd like things (and maybe additionally get flags).
    # I want a strlen to vaguely look something like this:
    # 
    # andi   0x7, s1, s2    // align pointer
    # ...                   // deal with start by masking out data
    # loop:
    # ld.d   (s2, s3)+, c1  // load d-word, increment indexed addr
    # cmp.b.m! c1, c_zero, c2 // compare bytes against c0, the zero reg, create flags and mask
    # bnz   loop        // was the result zero? no -> more
    # ctz   c2, s4      // find zero byte
    # addshifted.r    3, s4, s3
    # add   s2, s3, -s1 // wild addsub possible thanks to negation bits
    #
    # conditional on register value, more cal
    #
    # bnz   s7, whereever  // stage fusion/pseudo op, one stage creating the flags, control reacting to them without writeback
    # ok, strlen example was maybe stupid, jump could test mask
    #
#TODO: MAC
    # could get ugly if we want to support it on HW which only has microcoded mul
#TODO: Floating point helper
    # even if no FPU, certain helper (e.g. extract exponent), are more integer
    # bit shuffeling+adjust then floating point math.
    # with clever building blocks, basic fadd/fsub/fdouble/fhalf support is what?
    # 5 to 10 micro-ops?

    flags = 0
    if write_flags:
        flags = flags if ((res & SMASK_32) == 0) else flags | FLAG_S
        flags = flags if not res == 0 else flags | FLAG_Z
        # C/O nur wo die 3-Eingangs-Addierkette die Semantik traegt
        if mode_imm6 in (ArithMode.ADD, ArithMode.ADDC, ArithMode.ADDSHIFT1, ArithMode.ADDSHIFT2):
            u1 = s1 & MASK_RLEN; u2 = s2 & MASK_RLEN; u3 = s3 & MASK_RLEN
            i1 = u1 - 0x100000000 if (u1 & SMASK_32) else u1
            i2 = u2 - 0x100000000 if (u2 & SMASK_32) else u2
            i3 = u3 - 0x100000000 if (u3 & SMASK_32) else u3
            c_in = 1 if (mode_imm6 == ArithMode.ADDC and (flags_in & FLAG_C)) else 0
            raw_u = u1 + u2 + u3 + c_in
            raw_i = i1 + i2 + i3 + c_in
            if mode_imm6 == ArithMode.ADDC and inv_2:  # SUBB-Integration (Borrow-Zweig)
                u2_raw = src2 & MASK_RLEN
                raw_u = u1 + (~u2_raw & MASK_RLEN) + u3 + c_in
                if not cst_table:
                    i1s = -src1 if inv_1 else src1
                    borrow = 0 if (flags_in & FLAG_C) else 1
                    raw_i = i1s - src2 + s3 - borrow
            if mode_imm6 == ArithMode.ADDSHIFT1:
                raw_u = u1 + ((u2 << 1) & MASK_RLEN)
                raw_i = i1 + (i2 << 1)
            elif mode_imm6 == ArithMode.ADDSHIFT2:
                raw_u = u1 + ((u2 << 2) & MASK_RLEN)
                raw_i = i1 + (i2 << 2)
            if raw_u > MASK_RLEN:
                flags |= FLAG_C
            if raw_i > 0x7FFFFFFF or raw_i < -0x80000000:
                flags |= FLAG_O
        elif mode_imm6 == ArithMode.SLT and unsigned:
            u1 = s1 & MASK_RLEN; u2 = s2 & MASK_RLEN; u3 = s3 & MASK_RLEN
            if u1 + (~u2 & MASK_RLEN) + u3 > MASK_RLEN:
                flags |= FLAG_C
        # PADD64/MUL32ACC: dual-adder, 64-bit result — S von hi32, Z von (lo==0 and hi==0), C von finalem Carry
        elif mode_imm6 == ArithMode.PADD64:
            lo = (s1 & MASK_RLEN) + (s3 & MASK_RLEN)
            carry_lo = 1 if lo > MASK_RLEN else 0
            carry_hi = 1 if ((s2 & MASK_RLEN) + (aux_in & MASK_RLEN) + carry_lo) > MASK_RLEN else 0
            flags = 0
            if aux_cmp & SMASK_32: flags |= FLAG_S
            if res == 0 and aux_cmp == 0: flags |= FLAG_Z
            if carry_hi: flags |= FLAG_C
        elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MUL32ACC:
            if unsigned:
                prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)  # 64-bit unsigned
            else:
                i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
                i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
                prod = i1 * i2  # 64-bit signed
            prod_lo = prod & MASK_RLEN
            carry_lo = 1 if ((prod_lo & MASK_RLEN) + (s3 & MASK_RLEN)) > MASK_RLEN else 0
            carry_hi = 1 if ((((prod >> 32) & MASK_RLEN) + (aux_in & MASK_RLEN) + carry_lo) > MASK_RLEN) else 0
            flags = 0
            if aux_cmp & SMASK_32: flags |= FLAG_S
            if res == 0 and aux_cmp == 0: flags |= FLAG_Z
            if carry_hi: flags |= FLAG_C
        elif (mode_imm6 & ARITH4_MODE_MASK) in (ArithMode.MUL32, ArithMode.MULHI):
            # 64-Bit-Ergebnis: S = Sign des vollen Produkts (Bit31 des High-Worts),
            # Z = ganzes 64-Bit-Ergebnis null, O = 32-Bit-Sicht exakt (Truncation verlustfrei).
            # bit5: unsigned. Pragmatische Flags statt puristischer Orthogonalitaet.
            flags = 0
            hi_word = res if (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MULHI else aux_cmp
            lo_word = aux_cmp if (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MULHI else res
            if hi_word & SMASK_32: flags |= FLAG_S
            if res == 0 and aux_cmp == 0: flags |= FLAG_Z
            if mode_imm6 & 0x20:   # unsigned: exakt wenn hi == 0
                if hi_word != 0: flags |= FLAG_O
            else:                  # signed: exakt wenn hi == SignExt(lo)
                if hi_word != (0xFFFFFFFF if (lo_word & SMASK_32) else 0): flags |= FLAG_O
        elif (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.DIV:
            # K2: S=q-Sign, Z=q==0, O=div-zero|signed-overflow, C nicht abgeleitet.
            flags = 0
            if res & SMASK_32: flags |= FLAG_S
            if res == 0: flags |= FLAG_Z
            if div_zero_or_ovf: flags |= FLAG_O
        elif (mode_imm6 & ARITH4_MODE_MASK) in (ArithMode.MULFMA, ArithMode.MULFMS):
            # S/Z aus Basis (res). C=Carry(ADD)/no-borrow(SUB, SUBB-Konvention:
            # C=1 kein Borrow), O=Wrap (pragmatisch C==O, Akku-32-bit-Sicht).
            sub = (mode_imm6 & ARITH4_MODE_MASK) == ArithMode.MULFMS
            if unsigned:
                prod = (src1 & MASK_RLEN) * (src2 & MASK_RLEN)
            else:
                i1 = src1 - 0x100000000 if (src1 & SMASK_32) else src1
                i2 = src2 - 0x100000000 if (src2 & SMASK_32) else src2
                prod = i1 * i2
            hi = (prod >> 32) & MASK_RLEN
            if sub:
                borrow = (s3 & MASK_RLEN) < hi
                if not borrow: flags |= FLAG_C
                if borrow: flags |= FLAG_O
            else:
                carry = ((s3 & MASK_RLEN) + hi) > MASK_RLEN
                if carry: flags |= FLAG_C
                if carry: flags |= FLAG_O
    else:
        flags = flags_in

#TODO: Bypass is nice, but do we need it? is it usefull?
# this way one stage can only create flags, or we do not have to sweet so much
# where to inject prev_in for a nop, in the end the same:
# More degrees of freedom are nice, but adds HW
#TODO: also Bypass flags?
    real_res = 0
    if (prev_in_strobe & 8) == 8:
        real_res = prev_in
    else:
        real_res = res

    r_list = {'res': real_res & MASK_RLEN, 'flags': flags, 'aux': aux_cmp & MASK_RLEN }
    return r_list


##############################################################################
# --- DATENPFAD-PIPELINE ---

def execute_pipeline(in_a, in_b, in_c, ctrl, prev_in, flags_in, debug=False):
    """ Fuehrt die 4 Stufen hintereinander aus, liefert {'res': ..., 'flags': ...} """
    pi = ctrl['permb']
    res1 = permb(in_a, in_b, in_c, pi['src3_idx'], pi['cst_table'], pi['imm6'], flags_in, pi['mode_nibble'], pi['blank_enable'], prev_in, pi['prev_in_strobe'], pi['write_flags'], pi['read_flags'], pi['internal_table'], pi.get('aux_in', 0), pi.get('aux_strobe', 0), pi.get('shift_ctrl', False), pi.get('shift_left', False))
    if debug: print(f"permb:  {hex(res1['res'])}  aux={hex(res1['aux'])}")
    fi = ctrl['bitfrob']
    res2 = bitfrob(in_a, in_b, in_c, fi['mode_imm6'], res1['flags'], fi['inv_1'], fi['inv_2'], fi['inv_3'], res1['res'], fi['prev_in_strobe'], fi['src3_idx'], fi['cst_table'], fi['write_flags'], fi['read_flags'], fi['internal_table'], res1['aux'], fi.get('aux_strobe', 0))
    if debug: print(f"bitfrob:{hex(res2['res'])}  aux={hex(res2['aux'])}")
    ti = ctrl['ternlog']
    res3 = ternlog(in_a, in_b, in_c, ti['tern_lut'], res2['flags'], res2['res'], ti['prev_in_strobe'], ti['src3_idx'], ti['cst_table'], ti['write_flags'], ti['read_flags'], ti['internal_table'], ti.get('mask_mode', False), res2['aux'], ti.get('aux_strobe', 0))
    if debug: print(f"ternlog:{hex(res3['res'])}  aux={hex(res3['aux'])}")
    ai = ctrl['arith4']
    res4 = arith4(in_a, in_b, in_c, ai['mode_imm6'], res3['flags'], ai['inv_1'], ai['inv_2'], ai['inv_3'], res3['res'], ai['prev_in_strobe'], ai['src3_idx'], ai['cst_table'], ai['write_flags'], ai['read_flags'], ai['internal_table'], ai.get('op_type_1', OpType.SCALAR), ai.get('op_type_2', OpType.SCALAR), ai.get('op_type_3', OpType.SCALAR), res3['aux'], ai.get('aux_strobe', 0), ai.get('unsigned', False))
    return res4


def execute_microcode(in_a, in_b, in_c, ctrls, prev_in=0, flags_in=0, debug=False):
    """ Makro-Mikrocode-Stepper: 1 Aufruf = 1 Makro-Schritt (1 Pass durch den Block).
        DECODE (vor dem Block) liest Regs + synthetisiert Konstanten (Immediates,
        Masken, Escape-Vektoren) -> in_a/in_b/in_c. Der 4-Stufen-Block = 1 TDM-
        Execute-Phase (4 Phasen bei 4x Frequenz). WRITEBACK (nach dem Block) schreibt
        ins Registerfile. Mehrere Schritte = Makro-Mikrocode UEBER das Registerfile
        (Schritt N schreibt reg, Schritt N+1 liest reg). Simulator: in_a/b/c sind
        fix pro Aufruf, aber jeder Schritt kann per _in_a/_in_b/_in_c im ctrl-dict
        Operanden ueberschreiben (simuliert Registerfile-Re-Fetch).
        Ergebnis, Flags, und Aux jedes Schritts fliessen als prev_in/flags_in/aux_in
        an den naechsten Schritt. """
    aux = 0
    if isinstance(ctrls, dict):
        ctrls = [ctrls]
    for i, ctrl in enumerate(ctrls):
        _a = ctrl.get('_in_a', in_a)
        _b = ctrl.get('_in_b', in_b)
        _c = ctrl.get('_in_c', in_c)
        # Flache Kopie: Aufrufer-Dicts nicht mutieren (Bug-Fix)
        ctrl = {k: (dict(v) if isinstance(v, dict) else v) for k, v in ctrl.items()}
        ctrl['permb']['aux_in'] = aux
        out = execute_pipeline(_a, _b, _c, ctrl, prev_in, flags_in, debug=debug)
        prev_in = out['res']
        flags_in = out['flags']
        aux = out['aux']
        if debug: print(f"step {i}: {hex(prev_in)} flags={flags_in:#x} aux={hex(aux)}")
    return prev_in
