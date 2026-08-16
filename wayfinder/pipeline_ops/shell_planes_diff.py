"""Differential-Test: Shell ternlog/permb/bitfrob-Planen vs direkter pipeline-Aufruf."""
import sys, random
sys.path.insert(0, '/home/redbully/ecpu/requi/wayfinder/pipeline_ops')
import isa_shell
from isa_shell import ShellCPU, ternlog_w, permb_w, bitfrob_w
from pipeline import TernLut, BitFrobMode, ternlog, permb, bitfrob

random.seed(42)
fails = 0
for trial in range(25):
    a = random.getrandbits(32); b = random.getrandbits(32); c = random.getrandbits(32)
    lut = random.choice([TernLut.AND, TernLut.OR, TernLut.XOR, TernLut.XNOR, TernLut.MAJ, 0x96])
    # --- ternlog ---
    cpu = ShellCPU()
    cpu.write_dst(1, a); cpu.write_dst(2, b); cpu.write_dst(3, c)
    cpu.load_words(0x1080, [ternlog_w(lut, 5, 1, 2, 3)])
    cpu.run([0], start=0x1080, limit=1)
    r_ref = ternlog(a, b, c, lut, 0, 0, 0, False, False, False)['res']
    if cpu.read_dst(5) != r_ref:
        fails += 1; print(f"TERNLOG fail: shell={cpu.read_dst(5):08x} ref={r_ref:08x} lut={lut:02x}")
    # --- permb byte-mode ---
    cpu = ShellCPU()
    cpu.write_dst(1, a); cpu.write_dst(2, b); cpu.write_dst(3, c)
    cpu.load_words(0x1080, [permb_w(0, 6, 1, 2, 3)])
    cpu.run([0], start=0x1080, limit=1)
    r_ref = permb(a, b, c, 0, False, 0, 0)['res']
    if cpu.read_dst(6) != r_ref:
        fails += 1; print(f"PERMB fail: shell={cpu.read_dst(6):08x} ref={r_ref:08x}")
    # --- bitfrob LZC ---
    cpu = ShellCPU()
    cpu.write_dst(1, a)
    cpu.load_words(0x1080, [bitfrob_w(BitFrobMode.LZC, 7, 1)])
    cpu.run([0], start=0x1080, limit=1)
    r_ref = bitfrob(a, 0, 0, BitFrobMode.LZC, 0)['res']
    if cpu.read_dst(7) != r_ref:
        fails += 1; print(f"BITFROB fail: shell={cpu.read_dst(7)} ref={r_ref} a={a:08x}")

print(f"{'FAIL' if fails else 'OK'}: {25*3} Vergleiche, {fails} Mismatches")
sys.exit(1 if fails else 0)
