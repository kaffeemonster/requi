#!/usr/bin/env python
""" Makro-Op-DSL: benannte Pipeline-Ops -> ctrl-Dicts fuer execute_microcode.
    Bruecke zum Decoder: 1 Op = 1 Stufen-Befehl, step() baut den 4-Stufen-Pass.
    Op(stage, mode, ...) -> expand() -> Stufen-Sub-Dict, byte-identisch zu den
    handgeschriebenen ctrl-Dicts (helpers._b_*, ctrl_cmov, ...). """
from pipeline import ArithMode, BitFrobMode, OpType, TernLut

# Kanonische Bypass-Defaults — muessen byte-identisch zu helpers._b_perm/_b_bitf/_b_tern/_b_arit sein
_DEFAULTS = {
    'permb':   {'src3_idx': 0, 'cst_table': False, 'imm6': 0, 'mode_nibble': False,
                'blank_enable': False, 'prev_in_strobe': 8, 'write_flags': False,
                'read_flags': False, 'internal_table': False},
    'bitfrob': {'mode_imm6': BitFrobMode.LSR, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False,
                'read_flags': False, 'internal_table': False},
    'ternlog': {'tern_lut': 0x00, 'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False,
                'write_flags': False, 'read_flags': False, 'internal_table': False},
    'arith4':  {'mode_imm6': ArithMode.ADD, 'inv_1': False, 'inv_2': False, 'inv_3': False,
                'prev_in_strobe': 8, 'src3_idx': 0, 'cst_table': False, 'write_flags': False,
                'read_flags': False, 'internal_table': False},
}

class Op:
    """ Ein Stufen-Befehl. stage: 'permb'|'bitfrob'|'ternlog'|'arith4'.
        mode: BitFrobMode/ArithMode (bitfrob/arith4) bzw. tern_lut (ternlog, auch via mode).
        Alle anderen Felder optional, Default = Bypass. options: Dict mit Stufen-Extras
        (mode_nibble, blank_enable, imm6, shift_ctrl, shift_left, aux_in, aux_strobe,
        mask_mode, op_type_1/2/3, ...). """
    __slots__ = ('stage', 'mode', 'src3_idx', 'cst_table', 'tern_lut', 'mask_mode',
                 'inv_1', 'inv_2', 'inv_3', 'prev_in_strobe', 'write_flags', 'options')
    def __init__(self, stage, mode=None, *, src3_idx=0, cst_table=False, tern_lut=None,
                 mask_mode=False, inv_1=False, inv_2=False, inv_3=False,
                 prev_in_strobe=None, write_flags=False, options=None):
        if stage not in _DEFAULTS:
            raise ValueError(f"unbekannte Stufe: {stage}")
        self.stage = stage
        self.mode = mode
        self.src3_idx = src3_idx
        self.cst_table = cst_table
        self.tern_lut = tern_lut
        self.mask_mode = mask_mode
        self.inv_1 = inv_1
        self.inv_2 = inv_2
        self.inv_3 = inv_3
        self.prev_in_strobe = prev_in_strobe
        self.write_flags = write_flags
        self.options = dict(options) if options else {}

def expand(op):
    """ Op -> Stufen-Sub-Dict. Ausgehend vom Bypass-Default; nur gesetzte Felder ueberschreiben.
        Fuegt KEINE zusaetzlichen Keys hinzu (kein aux_in etc. ausser via options) —
        damit ist das Ergebnis byte-identisch zu den handgeschriebenen ctrl-Dicts. """
    d = dict(_DEFAULTS[op.stage])
    if op.stage in ('bitfrob', 'arith4') and op.mode is not None:
        d['mode_imm6'] = op.mode
    elif op.stage == 'ternlog':
        if op.tern_lut is not None:
            d['tern_lut'] = op.tern_lut
        elif op.mode is not None:
            d['tern_lut'] = op.mode
    if op.prev_in_strobe is not None:
        d['prev_in_strobe'] = op.prev_in_strobe
    if op.src3_idx:
        d['src3_idx'] = op.src3_idx
    if op.cst_table:
        d['cst_table'] = True
    if op.mask_mode:
        d['mask_mode'] = True
    if op.inv_1: d['inv_1'] = True
    if op.inv_2: d['inv_2'] = True
    if op.inv_3: d['inv_3'] = True
    if op.write_flags: d['write_flags'] = True
    d.update(op.options)
    return d

def bypass(stage):
    """ Bypass-Sub-Dict einer Stufe (prev_in-Strobe 8 = Passthrough). """
    return dict(_DEFAULTS[stage])

def step(*ops, _in_a=None, _in_b=None, _in_c=None):
    """ Ops -> kompletter ctrl-Pass fuer execute_microcode.
        _in_* nur setzen, wenn Operanden-Override gewuenscht (Regfile-Re-Fetch). """
    ctrl = {}
    for op in ops:
        ctrl[op.stage] = expand(op)
    if _in_a is not None: ctrl['_in_a'] = _in_a
    if _in_b is not None: ctrl['_in_b'] = _in_b
    if _in_c is not None: ctrl['_in_c'] = _in_c
    return ctrl
