"""isa_shell.py — Rumpf-Pipeline um die Kern-Pipeline (pipeline.py).

Sandwich-Simulator fuer die Papier-Encoding-Entwuerfe aus isa_vision.md:
    fetch -> decode -> [permb -> bitfrob -> ternlog -> arith4] -> writeback
Die Kern-Stufen kommen aus pipeline.py (execute_pipeline); diese Shell ergaenzt
PC, Register-File (C/S-Gruppen), Memory (RAM + MSR-pseudo-MMIO) und einen
rudimentaeren Decoder fuer die ISA-Formen.

ITERATION 1 (Kern-Zyklus): carith (F3) + sarith (F2-Sub) + Control (bra/brl/bxx)
+ Memory (ld/st). ternlog/permb/bitfrob-Planen: Lexikon reserviert, Exec folgt.

VEREINFACHUNGEN (Iteration 1, sind in isa_vision.md als offen markiert):
- bxx: Branch wenn (flags & mask) != 0; volle Bedingungs-Maschine offen.
- PC-relative: src1-Feld = 0 (S0, Zero-Reg) bedeutet PC-Basis.
- Memory-Adresse: base + idx + (offs << scale); Index byte-genau (unaligned),
  Offset breiten-skaliert (ARM-LDR-artig). Control: base + (idx << scale) + (offs*2 << scale).
- 1 Cycle/Instruktion (keine Pipeline-Stalls).
- unsigned-Signal: Assembler-Parameter (Encoding-Position im carith noch offen).
- MSR-Region (0x000-0xFFF): Vektor/IDENT/FLAGS/PC/CYCLE lesbar, Schreiben ignoriert.
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
    'FMEM': {'scale': (25, 24), 'off_hi': (23, 22), 'dst': (21, 17),
             'src1': (16, 13), 'src2': (12, 9), 'off_lo': (8, 0)},
}

# PLANES: opcode-Feld (29-26) -> (Form, Semantik)
PLANES = {
    0x0: ('F3', 'carith'),
    0x1: ('F3', 'ternlog'),
    0x2: ('F3', 'permb'),
    0x3: ('F3', 'bitfrob'),
    0x4: ('F2', 'subsplit'),   # Sub-Plane: 16 Sub-Instruktionen (c/s-Varianten)
    0x5: ('FMEM', 'control'),
    0x6: ('FMEM', 'memory'),
    # 0x7-0xF: frei (System/MSR, AMOD, float, MOVEM, ...)
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
    # 0xA-0xF: frei
}

# MSR-Region (pseudo-MMIO, 0x000-0xFFF); Register im untersten Block
MSR_VECTOR = 0x000  # Reset-Vektor: PC-Startwert (Wort)
MSR_IDENT = 0x004   # Feature/Ident-Register (lesbar)
MSR_FLAGS = 0x008   # Flags-Register (lesbar)
MSR_PC = 0x00C      # PC (lesbar; PC-relative Adressierung)
MSR_CYCLE = 0x010   # Cycle-Counter (lesbar)
MSR_END = 0x1000    # Ende der MSR-Region

RAM_SIZE = 0x10000
RESET_PC = 0x1000   # Default-Vektor

# Bypass-Sub-ctrls (Muster aus helpers.py: prev_in_strobe=8 = durchreichen)
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


def carith_w(mode, dst, s1, s2, s3=0, inv1=False, inv2=False, inv3=False,
             cst=False, wrf=False):
    """F3 carith: ctrl = inv3<<7 | inv2<<6 | inv1<<5 | mode(5)."""
    ctrl = (int(inv3) << 7) | (int(inv2) << 6) | (int(inv1) << 5) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 1 if cst else 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'opcode', 0x0, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


def ternlog_w(lut, dst, s1, s2, s3=0, wrf=False):
    """F3 ternlog: ctrl = LUT-Wert (256 Eintraege)."""
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', lut & 0xFF, FORMS['F3'])
    w = _set_bits(w, 'opcode', 0x1, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


def permb_w(mode, dst, s1, s2, s3, blank=False, wrf=False):
    """F3 permb: ctrl = blank<<7 | mode(5)."""
    ctrl = (0x80 if blank else 0) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'opcode', 0x2, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


def bitfrob_w(mode, dst, s1, s2, s3=0, inv1=False, inv2=False, inv3=False, wrf=False):
    """F3 bitfrob: ctrl = inv3<<7 | inv2<<6 | inv1<<5 | mode(5)."""
    ctrl = (0x80 if inv1 else 0) | (0x40 if inv2 else 0) | (0x20 if inv3 else 0) | (mode & 0x1F)
    w = 0
    w = _set_bits(w, 'src3', s3, FORMS['F3'])
    w = _set_bits(w, 'dst', dst, FORMS['F3'])
    w = _set_bits(w, 'src1', s1, FORMS['F3'])
    w = _set_bits(w, 'src2', s2, FORMS['F3'])
    w = _set_bits(w, 'cst', 0, FORMS['F3'])
    w = _set_bits(w, 'ctrl', ctrl, FORMS['F3'])
    w = _set_bits(w, 'opcode', 0x3, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
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
    w = _set_bits(w, 'opcode', 0x4, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


def sarithi_w(sub, mode, dst, s1, imm):
    """F1 sarith_imm: imm13 signed."""
    w = 0
    w = _set_bits(w, 'subop', sub, FORMS['F1'])
    w = _set_bits(w, 'dst', dst, FORMS['F1'])
    w = _set_bits(w, 'src1', s1, FORMS['F1'])
    w = _set_bits(w, 'imm', imm & 0x1FFF, FORMS['F1'])
    w = _set_bits(w, 'opcode', 0x4, {'opcode': (29, 26)})
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
    w = _set_bits(w, 'opcode', 0x5, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


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
    w = _set_bits(w, 'opcode', 0x6, {'opcode': (29, 26)})
    w = _set_bits(w, 'write_read_flags', 1 if wrf else 0, {'write_read_flags': (30, 30)})
    return w


def _sign11(x):
    x &= 0x7FF
    return x - 0x800 if x & 0x400 else x


def _sign13(x):
    x &= 0x1FFF
    return x - 0x2000 if x & 0x1000 else x


# ---------------------------------------------------------------------------
# CPU
# ---------------------------------------------------------------------------
class ShellCPU:
    """RF (C0-C15/S0-S15, C0/S0=Zero), PC, FLAGS, RAM 64K + MSR-Overlay, Zaehler."""

    def __init__(self, ram_size=RAM_SIZE, ident=0x00000001):
        self.rf = [0] * 32
        self.pc = RESET_PC
        self.flags = 0
        self.ram = bytearray(ram_size)
        self.cycle = 0
        self.ident = ident
        self.op_counts = {}
        self.halted = False
        # Reset-Vektor (Wort an 0x000) = RESET_PC
        _struct.pack_into('<I', self.ram, MSR_VECTOR, RESET_PC)

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
            return _struct.unpack_from('<I', self.ram, MSR_VECTOR)[0]
        return 0  # reserviert

    def mem_read(self, addr, size):
        if addr < MSR_END:  # MSR-Region abfangen
            val = 0
            for i in range(size):
                val |= (self.msr_read(addr + i) & 0xFF) << (8 * i)
            return val
        off = addr - MSR_END
        if off + size > len(self.ram):
            raise ValueError(f"mem_read out of range: 0x{addr:x}+{size}")
        return int.from_bytes(self.ram[off:off + size], 'little')

    def mem_write(self, addr, size, val, warn=True):
        if addr < MSR_END:
            if warn:
                print(f"WARN: mem_write in MSR-Region verworfen: 0x{addr:x} size={size}")
            return  # MSR-Region schreibgeschuetzt (Iteration 1)
        off = addr - MSR_END
        if off + size > len(self.ram):
            raise ValueError(f"mem_write out of range: 0x{addr:x}+{size}")
        self.ram[off:off + size] = (val & ((1 << (8 * size)) - 1)).to_bytes(size, 'little')

    # -- Decode -------------------------------------------------------------
    def decode(self, word):
        wf = (word >> 30) & 1
        opcode = (word >> 26) & 0xF
        plane = PLANES[opcode]
        form_name, sem = plane
        form = FORMS[form_name]
        dec = {'wf': wf, 'opcode': opcode, 'form': form_name, 'sem': sem,
               'plane': plane}
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
            if sub_form == 'F1':  # i-Version: src2 -> Imm13
                dec['dst'] = (word >> 17) & 0x1F
                dec['src1'] = (word >> 13) & 0xF
                dec['imm'] = _sign13(word & 0x1FFF)
            else:  # F2: 2-Op + ctrl
                dec['dst'] = (word >> 17) & 0x1F
                dec['src1'] = (word >> 13) & 0xF
                dec['src2'] = (word >> 9) & 0xF
                dec['cst'] = (word >> 8) & 1
                dec['ctrl'] = word & 0xFF
        return dec

    # -- Execute ------------------------------------------------------------
    def _arith(self, mode, a, b, c, inv1, inv2, inv3, wf, unsigned=False):
        out = execute_pipeline(a, b, c, _arith_ctrl(mode, inv1, inv2, inv3, wf, unsigned),
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
        c = self.read_c(dec['src3'])
        res, flags = self._arith(mode, a, b, c, inv1, inv2, inv3, bool(dec['wf']))
        if dec['wf']:
            self.flags = flags
        self.write_dst(dec['dst'], res)
        self._count(f"carith:{ArithMode(mode).name}")

    def _exec_ternlog(self, dec):
        from pipeline import ternlog
        lut = dec['ctrl']  # 8 Bit = voller 256-Eintraege-Ternaer-LUT-Wert
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        c = self.read_c(dec['src3'])
        res = ternlog(a, b, c, lut, self.flags, 0, 0, False, False, False)['res']
        self.write_dst(dec['dst'], res)
        self._count("ternlog")

    def _exec_permb(self, dec):
        from pipeline import permb
        ctrl = dec['ctrl']
        mode = ctrl & 0x1F
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
        c = self.read_c(dec['src3'])
        if dec['cst']:
            pass  # cst-Pool: Iteration 1 offen
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
        from pipeline import bitfrob
        a = self.read_c(dec['src1'])
        b = self.read_c(dec['src2'])
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
        else:  # F1 (i-Version): ADD-only (Iteration 1), b = Imm13
            mode = ArithMode.ADD
            inv1 = inv2 = inv3 = False
            a = self.read_s(dec['src1'])
            b = dec['imm']
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

    def _exec_ctrl(self, dec):
        scale = 1 << dec['scale_e']
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
        else:  # bxx: dst = Flagmaske, branch wenn (flags & mask) != 0
            self._count("bxx")
            taken = bool(self.flags & dec['dst'])
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

    # -- Stepper ------------------------------------------------------------
    def step(self, word, verbose=False):
        dec = self.decode(word)
        if verbose:
            print(f"pc=0x{self.pc:08x} word=0x{word:08x} {dec['plane']}")
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
            elif iname == 'sbitfrob':
                self._exec_sbitfrob(dec)
            elif iname == 'sshufb':
                self._exec_sshufb(dec)
            else:
                raise NotImplementedError(f"Sub-Op {iname} noch nicht in Shell (Iteration 1)")
        elif dec['form'] == 'FMEM':
            if dec['sem'] == 'control':
                self._exec_ctrl(dec)
            else:
                self._exec_mem(dec)
        self.cycle += 1
        if dec['sem'] not in ('control',):  # Branches setzen pc selbst
            self.pc = (self.pc + 4) & 0xFFFFFFFF

    def run(self, words, start=None, limit=100000, verbose=False):
        if start is not None:
            self.pc = start
        n = 0
        while n < limit and not self.halted:
            pc_off = self.pc - MSR_END
            if pc_off < 0 or pc_off + 4 > len(self.ram):
                raise ValueError(f"PC 0x{self.pc:x} ausserhalb RAM")
            word = int.from_bytes(self.ram[pc_off:pc_off + 4], 'little')
            self.step(word, verbose)
            n += 1
        if n >= limit and not self.halted:
            raise RuntimeError("Instruktions-Limit erreicht (Endlosschleife?)")
        return n

    def load_words(self, addr, words):
        base = addr - MSR_END
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
# Layout: Daten bei 0x1000 (RAM-Offset 0), Code bei 0x1080 (load_words).
# Relative Branch-Offsets sind layout-unabhaengig (PC-Basis).
# Imm13 signed reicht nicht fuer RAM-Basen >0xFFF (max 4095) -> 2x Add.
# ---------------------------------------------------------------------------
def build_smoke():
    S1, S2, S3 = 16 + 1, 16 + 2, 16 + 3   # S-Register-Nummern (global 5 Bit)
    C1, C2 = 1, 2
    prog = []
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 0, 0x800))    # S1 = 0x800
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 1, 0x800))    # S1 = 0x1000 (ptr)
    prog.append(sarithi_w(0x8, ArithMode.ADD, S2, 0, 1))       # S2 = 1 (cnt)
    prog.append(sarithi_w(0x8, ArithMode.ADD, S3, 0, 11))      # S3 = 11 (limit)
    prog.append(carith_w(ArithMode.ADD, C1, 0, 0, 0))          # C1 = 0 (sum)
    prog.append(mem_w(C2, 1, 0, 0, 2, wrf=False))              # loop: C2 = ld.w (S1)
    prog.append(carith_w(ArithMode.ADD, C1, 1, C2, 0))         # C1 += C2
    prog.append(sarithi_w(0x8, ArithMode.ADD, S1, 1, 4))       # S1 += 4
    prog.append(sarithi_w(0x8, ArithMode.ADD, S2, 2, 1))       # S2 += 1
    prog.append(sarith_w(0x0, ArithMode.CMP, 0, 2, 3, wrf=True))  # cmp S2,S3 -> Maske+Flags
    # CMP = Per-Lane-Gleichheits-Maske: res=0 (Z) wenn UNGLEICH, 0xFFFFFFFF (S) wenn gleich
    prog.append(ctrl_w(FLAG_S, 0, 0, 4, scale=0, wrf=True))    # bxx S -> exit (PC-Basis)
    prog.append(ctrl_w(0, 0, 0, -12, scale=0, wrf=False))      # bra loop (auf ld.w)
    prog.append(mem_w(C1, 1, 0, 0, 2, wrf=True))               # exit: st.w C1 -> (S1)
    prog.append(ctrl_w(0, 0, 0, 0, scale=0, wrf=False))        # bra . (halt)
    return prog


def run_smoke():
    cpu = ShellCPU()
    # Daten: 10 Worte 1..10 bei Adresse 0x1000 (RAM-Offset 0)
    for i in range(10):
        cpu.ram[4 * i:4 * i + 4] = (i + 1).to_bytes(4, 'little')
    prog = build_smoke()
    cpu.load_words(0x1080, prog)
    n = cpu.run(prog, start=0x1080)
    print(f"instruktionen: {n}, cycle: {cpu.cycle}")
    print(f"op-counts: {dict(sorted(cpu.op_counts.items()))}")
    print(f"C1 (Summe 1..10): {cpu.read_dst(1)}  (erwartet 55)")
    print(f"RAM[0x1028] (st.w Ergebnis): {int.from_bytes(cpu.ram[0x28:0x2C], 'little')}")
    print(f"Flags: 0x{cpu.flags:x}  PC: 0x{cpu.pc:x}")
    ok = (cpu.read_dst(1) == 55
          and int.from_bytes(cpu.ram[0x28:0x2C], 'little') == 55
          and cpu.flags & FLAG_S)
    print("SMOKE:", "PASS" if ok else "FAIL")
    return ok


if __name__ == '__main__':
    ok = run_smoke()
    import sys
    sys.exit(0 if ok else 1)
