# eCPU Pipeline — Operations Survey

Pipeline: `permb → bitfrob → ternlog → arith4` (4 TDM sub-phases per pass).
ISA = contract; HW = abstracted. Small chip may be slow but complete.

---

## State at a Glance

### ArithMode (arith4 stage)
| # | Name | What | Lane |
|---|------|------|------|
| 0 | — | unused (res=0) | — |
| 1 | **ADD** | s1+s2+s3; sub via inv_2/inv_3 | SCALAR |
| 2 | **ADDC** | s1+s2+s3+C_flag | SCALAR |
| 3 | **PADD** | packed add, carry broken at lanes | op_type_1 |
| 4 | **USATADD** | unsigned saturating add clamp 0xFFFFFFFF | SCALAR |
| 5 | **SATADD** | saturating signed add | SCALAR |
| 6 | **AVG** | (s1+s2+(s3&1))>>1 rounding avg | SCALAR |
| 7 | **ABSADD** | \|s1\|+s2+s3 | SCALAR |
| 8 | **CMP** | cmp mask (0xFF/0xFFFF per lane) | op_type_1 |
| 9 | frei | — | — |
| 10 | **SLT** | signed < mask (s3: 1=<,0=≤; Sign-Flip-Borrow, overflow-sicher) | SCALAR |
| 11 | **SLTU** | unsigned < mask | SCALAR |
| 12 | **MFC** | carry_flag → 0/1 value | SCALAR |
| 13 | **ADDSHIFT1** | s1+(s2<<1) lea ×3 | SCALAR |
| 14 | **ADDSHIFT2** | s1+(s2<<2) lea ×5 | SCALAR |
| 15 | **PMIN** | packed min (s3 bit0: sign) | op_type_1 |
| 16 | frei | — | — |
| 17 | **PMAX** | packed max (s3 bit0: sign) | op_type_1 |
| 18 | frei | — | — |
| 19 | **PSADD** | packed saturating add | op_type_1 |
| 20 | frei | — | — |
| 21 | **PSSUB** | packed saturating sub | op_type_1 |
| 22 | frei | — | — |
| 23 | **PWADD** | (s1+(s1>>lb))&mask SWAR horiz | op_type_1 |
| 24 | **PSADB** | s3+Σ\|byte(s1)-byte(s2)\| SAD | BYTE |
| 25 | **SUBB** | s1-s2-s3-~C (ARM SBC, borrow=~C) | SCALAR |
| 26 | **MUL** | 16×16→32 unsigned (s1[15:0] * s2[15:0]) | SCALAR |
| 27 | **MULADD** | s3 + 16×16→32 unsigned accumulate | SCALAR |
| 28 | **MUL32** | 32×32→64. bit5=0=signed, bit5=1=unsigned. res=lo32, aux=hi32 | SCALAR |
| 29 | **MULHI** | 32×32 hi32. bit5 selects signed/unsigned. res=hi32, aux=lo32 (symmetrisch zu MUL32) | SCALAR |
| 30 | **PADD64** | 64-bit Add (32-bit Lane-Break im Datapfad): s1+s3=lo, s2+aux_in+carry=hi. res=lo, aux=hi | SCALAR |
| 31 | **MUL32ACC** | 32×32→64 MAC. bit5 selects signed/unsigned. prod=s1*s2, lo=prod_lo+s3, hi=prod_hi+aux_in+carry. res=lo, aux=hi | SCALAR |

Freed: 9,16,18,20,22 (5 slots).
Lane width: op_type_1 (BYTE=8 / WORD=16 / SCALAR=32). s3 bit0: 0=unsigned 1=signed.

### BitFrobMode (bitfrob stage)
| # | Name | What | LUT |
|---|------|------|-----|
| 0 | **LSR** | logical right (0..7 fine) | ~30 |
| 1 | **LSL** | logical left (0..7 fine) | ~30 |
| 2 | **ROR** | rotate right (0..7 fine) | ~30 |
| 3 | **ASR** | arithmetic right (0..7 fine) | ~30 |
| 4 | **BITREV8** | bit-reverse per byte | ~0 |
| 5 | **LZC** | leading zero count | ~40 |
| 6 | **TZC** | trailing zero count | ~40 |
| 7 | **MASK** | c≠0→all-ones else 0 | ~10 |
| 8 | **ROL** | rotate left (0..7 fine) | ~30 |
| 9 | **SEXT** | sign-extend from bit (s3&31) | ~40 |
| 10 | **POPCNT_N** | popcount per nibble (0..4) | ~55 |
| 11 | **POPCNT_B** | popcount per byte (0..8) | ~80 |
| 12 | **MASKW** | (1<<n)-1, n=0→32 | ~30 |
| 13 | **CLMUL_LO** | GF(2) byte-mul low | ~120 |
| 14 | **CLMUL_HI** | GF(2) byte-mul high | ~120 |
| 15 | **PARITY_B** | parity per byte (4×8→1 XOR) | ~30 |
| 16 | **PARITY_W** | parity 32→1 XOR | ~16 |
| 17 | **POLY_RED** | GF(2) reduction s1 mod s3 | ~60 |
| 18 | **BITZIP_8** | Zero-Interleave lower byte→16b | ~30 |
| 19 | **BITUNZIP_8** | Compact even bits 16b→byte | ~30 |
| 20 | **GFNI_AFFINE** | AES affine 5-bit XOR window | ~40 |
| 21 | **BITSWAP** | Butterfly XOR-swap | ~50 |
| 22 | **NIBLKP** | Nibble lookup in BITFROB_CST | ~0 |
| 23 | **BCD_HC** | BCD Half-Carry per byte | ~20 |
| 24 | **BMATOR** | Bit Matrix OR: OR ROR(b,k) ∀ a[k]=1 | ~230 |
| 25 | **BMATXOR** | Bit Matrix XOR: XOR ROR(b,k) ∀ a[k]=1 | ~30 (ROR-bank shared) |
| 26 | **BMAT_N_OR** | BMM per nibble OR (4b ROR, 8 parallel) | ~50 |
| 27 | **BMAT_N_XOR** | BMM per nibble XOR (XOR tree) | ~10 extra |
| 28 | **LOG2** | floor(log2): 31-LZC, 1-pass | ~5 |
| 29 | **LOG10** | floor(log10): 9 comparators + prio enc | ~50 |
| 30 | **SHR_STICKY** | fine LSR 0..7 + sticky (shifted-out→aux+FLAG_O) | ~15 |
| 31 | **PEXT_N** | pext nibble-level (mask=s2&0xFF, 8× 4-bit mux) | ~50 |
| 32 | **PDEP_N** | pdep nibble-level (same HW reversed direction) | ~50 |

Total bitfrob LUT budget: ~35 (shifts) + ~160 (count/parity) + ~120 (CLMUL) + ~60 (POLY_RED) + ~150 (bitzip/GFNI/BITSWAP) + ~280 (BMATOR/XOR) + ~60 (BMAT_N) + ~55 (LOG2/LOG10) + ~15 (SHR_STICKY) + ~100 (PEXT_N/PDEP_N) ≈ 1035 LUT.
All modes together ≈ 15.2× single ternlog reference (68 LUT). BMATOR/BMATXOR share 32×32 crossbar + AND-plane; OR-tree/XOR-tree differ.

z3 verified (pipeline_smt.py M16, Q81-Q86, ∀ symbolic, 82 realisierbare + 3 unmögliche Lemmas): BCD_HC == per-nibble carry; LOG2 == 31−LZC (2^r ≤ x < 2^(r+1), x==0 → 0xFFFFFFFF); LOG10 == 9-Schwellen-Summe; BITZIP_8 == pdep(x,0x5555) und BITUNZIP_8 == pext(x,0x5555) (Morton == M6-Butterfly, Kreuz-Link); GFNI_AFFINE == x ^ ROL8(x,k) k∈{1,2,3,4} ^ c (Row-Bits {i,i+4,i+5,i+6,i+7}). Modell==Pipeline transitiv via 69/69-Referenz-Batterie.

### Infrastructure
| Component | Bits | Cost | Notes |
|-----------|------|------|-------|
| **TernLut** (named constants) | 8-bit LUT | 68 LUT | 14 named values: CLR,AND,OR,XOR,NOT,ANDNOT,ANDNOT_C,ORC,MOV_A/B/C,SELECT_A/B,MANDN,SET |
| **OpType** per operand | 2-bit ×3 | 0 LUT | SCALAR/BYTE/WORD; decoder wires through control path |
| **Aux line** | 32-bit + strobe | ~40 LUT + 4×32 FF | 2nd pipeline slot, per-stage tap, decoder-internal |
| **prev_in_strobe** | 4-bit | 0 LUT | bits 1/2/4→inject prev into s1/s2/s3; bit 8→bypass |
| **CST tables** | 4 arrays, variable sizes | config ROM | ISA=16 visible; decoder escape=unlimited. Sizes: PERMB 32 (+ PERMB_NIB_CST 32), BITFROB 48 (incl GF(2^4) inv), TERNLOG 288 (incl AES S-box ROM), ARITH 32 (22-31 = float consts) |
| **mask_mode** (ternlog) | 1-bit | ~5 LUT | width-mask from src3_idx, frees bitfrob for shift |
| **shift_ctrl** (permb) | 1-bit | ~30 LUT | AltiVec-lvsr-style: src3=shift amt 0..31, permb synthesizes byte-shift mask on-the-fly (byte part n>>3); bitfrob does fine part (n&7); shifted-out bytes→aux+FLAG_O. shift_left: direction. ⚠ braucht blank_enable=True (synthetisierte 0x80-Marker; mit False wird 0x80 als Index 0 gelesen → stilles Garbage, z3-M14-Befund) |

---

## What's Free (1 pass, no new HW)

### Arithmetic
ADD, SUB (inv), ADDC (carry-in+out), SUBB (borrow-in+out, ARM SBC), NEG (inv or dec constant), ABS (ABSADD), SATADD (saturating signed), USATADD (unsigned sat clamp 0xFFFFFFFF), AVG (rounding average), ADDSHIFT1/2 (lea ×3/×5). MUL 16×16→32 (unsigned). MUL32/MULHI 32×32→64 signed AND unsigned (bit5=1 → zero-extend operands, same multiplier array, 0 LUT extra). MUL32ACC signed+unsigned MAC (bit5). PADD64 64-bit add via dual 32-bit adder (s1+s3=lo, s2+aux+carry=hi, ~64 LUT extra). MUL 16×16→32 unsigned (1 pass, ~250 LUT or DSP). MULADD accumulate. MUL32 32×32→64 signed (1 pass, ~500 LUT or DSP), aux=hi32. MULHI 32×32 signed hi32. MUL32ACC 32×32→64 signed MAC (1 pass, DSP cascade: MUL + dual adder). 32×32 unsigned microcode path also possible from 16×16 primitives (6-8 passes). MAC = MUL32 + MUL32ACC = 2 passes. 64-bit mul flags (MUL32/MULHI, pragmatisch): S = Sign des vollen 64-Bit-Produkts (Bit31 des High-Worts), Z = ganzes 64-Bit null, O = 32-Bit-Sicht exakt (unsigned: hi==0; signed: hi==SignExt(lo)). MULHI aux=lo32 (MUL32 aux=hi32 — Paar-Konvention, MAC-Kette nutzt es). MUL32ACC bit5-maskiert in Flags (Z korrekt fuer unsigned).

### Compare & Flags
SLT/SLTU mask (signed/unsigned <,≤; SLT = Sign-Flip-Borrow, gleiche HW wie SLTU, overflow-sicher — z3 M12 Q61/Q62), CMP packed mask, flags write (S,Z,C,O), MFC (carry→register), test/bittest (ternlog AND+LZC/TZC). permb blank-event → FLAG_O (presence/validity signal, free metadata; write_flags off prevents congestion). BITSET_ADD x+(1<<n) (permb shift_ctrl LSL + ROL fine + ADD, 1 pass, z3 M14 Q73). SUBNET /n (MASKW(32-n)+NOT, 1 pass, /32-Edge = Decode-Sonderfall).

### Bitwise Logic (ALL via TernLut)
AND, OR, XOR, NOT, ANDNOT, ANDNOT_C, ORC, MOV_A/B/C, SELECT_A/B, MANDN (0x6A = (a&b)^c, Masked-AND mit XOR-Maske, Baugh-Wooley-Komposition), CLR, SET.
Any 1-bit truth table (256 possibilities) in 1 pass.

### Conditional Move / Min / Max
CMOV: bitfrob MASK(c≠0) → ternlog SELECT → 1 pass.  
Scalar min/max: PMIN/PMAX with op_type=SCALAR → 1 pass.

### Packed (SIMD) Family
PADD (add), PADD+inv_2 (wrapping sub), CMP (mask), PMIN/PMAX (min/max), PSADD/PSSUB (saturating add/sub). All lane widths via op_type_1.

### Shifts & Rotates
LSR/LSL/ASR/ROR/ROL fine (0..7 bits, 1 pass). BITREV8 (0-cost cross-wiring). Byte-multiple rotates via permb escape vectors (1 pass for rotate, 2 for shift). Dynamic byte shift: permb shift_ctrl (src3=amt 0..31, synthesizes mask on-the-fly, AltiVec-lvsr style; fine part n&7 in bitfrob; ⚠ blank_enable=True nötig). SHR_STICKY (fine LSR + sticky/guard for float rounding, shifted-out→aux+FLAG_O). ⚠ bitfrob LSL leaket s2 (res=(s1<<f)|(s2>>(32-f)), s2 muss 0 sein) während permb shift_ctrl den Wert in s2 braucht → ROL ist s2-sicher, wrappt aber s1 ((s1>>(32-f))-Term): Wert 1 in s2 → ROL sicher (BITSET-Trick); dichte Werte → MASKW+NOT statt Shift. Operanden-Platzierung: MASKW-Breite → s3, shift_ctrl-Menge → s3, LSL-Wert → s1, LSR-Wert → s2.

### Bitfield Extract / Insert
SEXT (sign-extend 1 pass). UBFX lsb≤7 (ROR+AND, 1 pass). BFI lsb=0 (ternlog SELECT, 1 pass). UBFX lsb>7 / BFI lsb>0: 2 macro-steps (shift→writeback→blend). Mask created by decoder from immediate.

### Count / Pop / Scan / Parity
LZC, TZC (1 pass). POPCNT_N/B (SWAR popcount per nibble/byte, 1 pass). Full 32-bit popcount: 3-step microcode. Byte-scan: CMP+LZC. PWADD (pairwise widen-add, SWAR horiz sum, 1 pass). PSADB (sum-of-absolute-differences, 1 pass). PARITY_B/W (byte/word parity, 1 pass); nibble parity via ternlog AND 0x11111111; halfword via byte parity XOR.

### GF(2) / CRC / Crypto
CLMUL_LO/HI (GF(2) byte multiply, 1 pass). POLY_RED (GF(2) reduction, 1 pass). Full GF(2⁸) multiply: 3 passes (CLMUL_LO+HI+POLY_RED). xtime: LSL+POLY_RED (2 passes). CRC32 Barrett: ~6-8 macro-steps. Hash mix constants in ARITH_CST.

### Exotic
Binary↔Gray: 2c (shift+ternlog XOR). ALPHA zap/extr: 2-3c (ternlog+strobe). Integer log2: LOG2 1-pass or 2c microcode. Integer log10: LOG10 1-pass (~20c true microcode). BITZIP_8/BITUNZIP_8 (scalar via permb, 5 macro-steps). GFNI affine (1 pass). BITSWAP butterfly (1 pass). 8×8 transpose (6 passes BITSWAP). NIBLKP nibble S-box lookup (1 pass, orthogonal). GF(2^8) S-box: composite ~10c or ROM 1c via TERNLOG_CST. Nibble permute (permb mode_nibble): full 16-nibble selection from both src registers (4-bit index, no blank), own PERMB_NIB_CST with gather/low-high/zip/lane-swap vectors.

---

## What's Microcode (2+ passes, no new HW)

| Op | Passes | Pattern |
|----|--------|---------|
| Full 32-bit popcount | 3 | POPCNT_B + PWADD(BYTE) + PWADD(WORD) |
| Full 32-bit CLMUL | 10-15 | permb byte-split + 16×CLMUL_B + ternlog XOR + PWADD |
| CRC32 Barrett | 6-8 | 3×CLMUL + XOR |
| GF(2⁸) multiply | 3 | CLMUL_LO + CLMUL_HI + POLY_RED |
| xtime (AES) | 2 | LSL + POLY_RED |
| Full rotate (32-bit) | 2 | permb escape + fine ROL/ROR |
| UBFX lsb>7 | 2 | permb/ROR shift → AND mask |
| BFI lsb>0 | 2 | permb/ROL shift → ternlog blend |
| Round-to-power-of-two | 2 | LZC + LSL + mask |
| Scalar min/max (flags) | 2 | SLT mask (overflow-safe, z3 M12 Q61/Q62) + ternlog SELECT |
| SADDI x+((y<<sh)^m) | 2 | ROL fine + ternlog XOR → arith4 ADD (4 Werte > 3 Operanden-Slots; z3 M14 Q74) |
| Boothe step | 2 | MASK(MplierBit) + LSL+mask_mode+ADD |
| Full BMM (nibble microcode) | ~10 | 8× BMAT_N + permb position + ternlog XOR |
| Multi-word subtract (64-bit) | 2 | SUBB lo + SUBB hi (C flag flows between steps) |
| Full 32×32→64 signed multiply | 1 | MUL32/MULHI |
| Full 32×32→64 unsigned multiply | 1 | MUL32/MULHI bit5=1 |
| Full 32×32→64 multiply (unsigned, no HW) | 6-8 | Schoolbook: 4× MUL16 + 3× PWADD/ADD |
| String compare/length | 2-3 | CMP mask + LZC/TZC |
| SHA/MD5 round | 2-3 | ADD + ternlog ROT/XOR + PWADD |
| AES MixColumns | 3-4 | CLMUL_B + ternlog XOR + permb |
| CTZ-MUL | N×N/2 | TZC + conditional ADD + shift |

---

## True Gaps (need new HW block)

| # | Gap | LUT est. | Priority | Notes |
|---|-----|----------|----------|-------|
| 1 | (resolved — AES S-box: composite-field path DEMOED in TEST 35, 256/256, ~340 LUT, NIBLKP+gf4_mul+GFNI_AFFINE; ROM path also works) | | | |
| 2 | **Wide barrel shifter** | ~350 | LOW | Deliberate tradeoff: fine 0..7 in bitfrob, byte via permb. 2-pass rotate accepted. |
| 3 | (resolved — PEXT_N/PDEP_N nibble-level ~50 LUT each + 5-stage butterfly microcode for full 32-bit pext/pdep, TEST 39, all pipeline primitives; naive nibble-pack wrong for non-uniform masks, butterfly needed) | | | |
| 4 | **Packed multiply** | (depends on mul) | LOW | Wait for scalar mul; then lane-breaks. |

Resolved: GFNI_AFFINE=20 (~40 LUT, bitfrob), flag-only CMP (SUB→zero-reg + write_flags, 0 HW), integer multiply (MUL32/MULHI signed+unsigned, 1-pass, bit5 flag), AES S-box composite-field path (TEST 35, 256/256 verified, NIBLKP+gf4_mul+GFNI_AFFINE, ~340 LUT, maps = Canright CHES 2005 decoder XOR eqns), pext/pdep (PEXT_N=31/PDEP_N=32 nibble-level ~50 LUT each, full 32-bit via 5-stage HD-butterfly microcode TEST 39). Old mul gap #1 → done.

### S-box: two paths
**ROM** (TERNLOG_CST extended to 288 entries): 1-pass via ternlog MOV_C (lut=0xAA) + cst_table. 256-byte AES S-box verified (256/256 correct). Camellia/SM4/any 8-bit S-box = another 256-entry table extension. Cost: 1 BRAM18k per 256 entries.

**Composite field** (no new block): GF(2⁸)→GF(2⁴)² map (ternlog XOR, ~80 LUT) + GF(2⁴) inverse (16-entry BITFROB_CST index 32-47, NIBLKP) + GF(2⁴) multiply (CLMUL+POLY_RED, 0x13 poly) + inverse map (ternlog, ~80 LUT) + affine (ternlog+ARITH_CST 0x63, ~40 LUT). Total ~340 LUT, 6-10 macro-steps. Map equations = decoder problem, not HW problem (Canright CHES 2005 matrices).

---

## Per-Category Reference

### A: Basic Arithmetic — DONE
ADD/SUB/NEG/ADDC/ABS/SATADD/AVG/ADDSHIFT1/2 all 1 pass. MUL 16×16→32 (1 pass, DSP/~250 LUT). MUL32 32×32→64 signed (1 pass, aux=hi32). MULHI 32×32 hi32 (aux=lo32). MULADD accumulate. 32×32 unsigned via microcode from 16×16 primitives.

### B: Compare/Flag — DONE
SLT/SLTU/CMP/MFC all 1 pass (CMP = SUB→zero-reg + write_flags; decoder can skip writeback via strobe 8). Flags S,Z,C,O written by arith4 ADD-family modes.

### C: Bitwise/Bitfield — DONE
All ternlog LUTs named. MASK/MASKW/SEXT 1 pass. UBFX/BFI: 1 pass when lsb≤7, 2 macro-steps otherwise. mask_mode in ternlog frees bitfrob. Pext/Pdep deferred (gap #4).

### D: Shifts/Rotates — DONE
Fine shifts (0..7) all modes. BITREV8. Byte multiples via permb escape. Full rotate = 2 passes. Wide barrel = gap #3 (accepted tradeoff).

### E: Select/Move — DONE
CMOV 1 pass. Scalar min/max 1 pass (PMIN/PMAX SCALAR). Blend via ternlog SELECT.

### F: SIMD/Packed — DONE
PADD/CMP/PMIN/PMAX/PSADD/PSSUB unified via op_type_1. Wrapping sub = PADD+inv_2. Saturating scalar sub = PSSUB SCALAR (new). Packed mul = gap #5.

### G: Count/Pop/Scan/Parity — DONE
LZC/TZC 1 pass. POPCNT_N/B 1 pass. Full popcnt 3-step. PWADD 1 pass. PSADB 1 pass. Byte-scan 2-3c. PARITY_B/W 1 pass.

### H: String — MICROCODE
All expressible via CMP+LZC/TZC+permb in 2-4 passes. No dedicated HW needed.

### I: Carry-less / CRC — DONE
CLMUL_LO/HI 1 pass. POLY_RED 1 pass. GFNI_AFFINE 1 pass. Full GF(2⁸) mul = 3 passes. CRC32 = 6-8 passes. xtime = 2 passes.

### J: Crypto/Hash — MOSTLY DONE
Hash mixes (ADD+ROT+XOR) composable. AES S-box: composite path viable, dedicated ROM optional (gap #2). MixColumns microcode-able from CLMUL_B+ternlog+permb.

### K: Special Integer — DONE
Log2/log10 1-pass. MUL 16×16→32 1-pass. MUL32/MULHI 32×32→64 signed+unsigned 1-pass (bit5 flag, same multiplier array, 0 LUT extra). MUL32ACC signed+unsigned MAC 1-pass. Schoolbook unsigned 32×32 without DSP = 6-8 microcode. Magic mul helpers via ARITH_CST.

### L: Exotic/Niche — MOSTLY MICROCODE
Gray↔Binary done. BITZIP_8/BITUNZIP_8 1 pass bitfrob, scalar via permb. GFNI_AFFINE 1 pass. BITSWAP 1 pass. 8×8 transpose demo (6c). BMM, BCD, blends, soft-float — microcode-able or deferred.

---

## HW Cost Summary (Gowin 4-LUT reference)

| Block | LUT | vs ternlog (68) |
|-------|-----|-----------------|
| ternlog (64-bit LUT) | 68 | 1.0× |
| bitfrob shift block (LSR/LSL/ROR/ROL/ASR) | ~35 | 0.5× |
| LZC/TZC | ~40 | 0.6× |
| POPCNT_N | ~55 | 0.8× |
| POPCNT_B | ~80 | 1.2× |
| MASKW | ~30 | 0.4× |
| PARITY_B | ~30 | 0.4× |
| PARITY_W | ~16 | 0.2× |
| BITREV8 | ~0 | 0× |
| CLMUL_B (LO+HI, shared AND-plane) | ~120 | 1.8× |
| POLY_RED | ~60 | 0.9× |
| PWADD | ~35 | 0.5× |
| PSADB | ~110 | 1.6× |

All post-bitfrob modes stay ternlog-class (≤2×). True costly blocks: integer mul (>7×), wide barrel (>5×), AES S-box ROM.

---

## Full Chip LUT Estimate (Tang Nano 9K target: GW1NR-9, 8640 LUT)

### CPU Core (~2900 LUT)
| Block | LUT | Notes |
|-------|-----|-------|
| 4-stage pipeline (full) | ~1684 | permb+bitfrob+ternlog+arith4, all modes incl dual-adder (PADD64/MUL32ACC) |
| Register file (32×32-bit, 2R1W) | ~400 | Dual-port read + single write |
| Decoder + macro-sequencer | ~600 | Immediate synthesis, CST escape, microcode ROM |
| Writeback + forwarding | ~200 | Post-block writeback, bypass network |
| PC + branch unit | ~300 | Branch predictor, PC chain, link register |
| Interrupt/exception controller | ~200 | Vector table, priority, save/restore |
| **Core subtotal** | **~3324** | |

### Uncore (~2300 LUT)
| Block | LUT | Notes |
|-------|-----|-------|
| L1 I-cache (4KB) | ~400 | Direct-mapped, 32-byte lines |
| L1 D-cache (4KB) | ~400 | Write-through or write-back |
| Memory bus / AXI lite | ~400 | Burst support, FIFO |
| UART + SPI + I2C | ~400 | Full peripherals |
| GPIO + timers | ~200 | 32 GPIO, 2×32-bit timers |
| Debug/JTAG | ~200 | Single-step, breakpoints |
| Glue + clock domain | ~300 | Reset, clock gating, TDM phase gen |
| **Uncore subtotal** | **~2300** | |

### Totals
| | LUT | % of chip |
|---|-----|-----------|
| CPU Core | ~3324 | 38% |
| Uncore | ~2300 | 27% |
| **Used** | **~5624** | **65%** |
| Free margin | ~3016 | 35% — int mul (signed done), bigger caches, extra peripherals |

TDM 4-phase execute saves ~200-300 pipeline registers vs traditional 5-stage pipe. Pipeline alone is ~19% of 8640 LUT — plenty of room for a complete RISC-class CPU with SIMD and crypto.

---

## Open TODOs (from pipeline.py hill)

**Worth doing:**
- [x] bitzip.8 / unzip.8 → BITZIP_8(18)/BITUNZIP_8(19) in bitfrob, scalar via permb
- [x] 8×8 bit transpose (vgbbd) → BITSWAP 3-stage butterfly demo
- [x] helper for ARM64-style immediate creation → imm_encode(val) in pipeline.py
- [x] GFNI affine transform byte → GFNI_AFFINE=20 in bitfrob, ~40 LUT
- [x] flag-only compare → CMP = SUB→zero-reg + write_flags; decoder skip-writeback via strobe 8
- [x] Integer multiply → MUL(26)/MUL32(28)/MULHI(29)/MUL32ACC(31). Signed 32×32→64 done. Unsigned via 16×16 microcode
- [x] BCD_HC → DAA/DCOR 4-pass microcode from BCD_HC(23) primitive
- [x] Nibble-mode S-box table (NIBLKP + extended CST done; 256-entry S-box ROM in TERNLOG_CST done; composite-field path DEMOED in TEST 35, 256/256)
- [ ] Wide barrel shifter (gap #3 — accepted tradeoff)
- [x] BCD acceleration → BCD_HC=23 (binary half-carry primitive); DAA = BCD_HC + ternlog >9-check + ternlog SELECT + arith4 ADD (4-pass microcode)
- [x] BMM → BMATOR(24)/BMATXOR(25) 1-pass + BMAT_N_OR(26)/BMAT_N_XOR(27) nibble primitive
- [x] LOG2(28) 1-pass (~5 LUT), LOG10(29) 1-pass (~50 LUT comparator chain)
- [x] pext/pdep → PEXT_N(31)/PDEP_N(32) nibble primitives (~50 LUT each); full 32-bit via 5-stage butterfly microcode (HD pext32 + inverse-butterfly pdep32, TEST 39, all pipeline primitives, ~75 passes)

**Deferred / low priority:**
- [ ] shufbitmb / compress / TBM
- [ ] masked-set ops
- [x] soft-float helpers → shift_ctrl (permb, AltiVec-lvsr dynamic byte shift) + SHR_STICKY(30) (guard/sticky rounding) + ARITH_CST float consts (22-31: bias 127, 1.0f/0.5f, ±inf, NaN, 2^23, max denorm, min normal). Float add 12-15→6-8 passes, mul 8-10→5-7, FMA ~10→4-6
- [x] nibble-mode permb cst table (separate from byte-mode) → PERMB_NIB_CST 32 entries; nibble mode now full 16-nibble selection (4-bit index, no blank bit); blank via ternlog AND/mask_mode
- [x] write flags for blank/enable events → permb sets FLAG_O on any blank (byte mode); metadata falls out free; flags-off switch (write_flags=False) prevents writeback congestion

**Design questions (not action items):**
- bypass flags as well as data?
- simplify strobe injection to single position?
