# AGENTS.md — CPU-ISA Wayfinder (`pipeline_ops/`)

Kurzreferenz fuer Agenten, die in diesem Ordner arbeiten. Ergaenzt (nicht ersetzt)
`isa_vision.md` (Design-Vision) und `ops_survey.md` (Op-Bestand). Bei Widerspruch:
Code > `isa_vision.md` > dieses Dokument.

## Was ist das?

Entwurf einer **neuen CPU-ISA** samt Simulations- und Beweis-Infrastruktur.
Leitprinzip: **Die ISA ist die API. Hardware ist die Implementierung.**
"Wie wer was giesst, egal, hauptsache API-konform."

- **Reiche Basis-ISA** (bewusst anti-RISC-V-Sparsamkeit): viele Ops kosten fast nichts
  (ternlog 64-bit ≈ 68 LUT; ein Power-On-Reset ≈ 70 LUT). Abspecken nur als separates
  E/lite-Release, nie in der gemeinsamen Basis.
- **Kern:** 4 Pipeline-Stufen `permb -> bitfrob -> ternlog -> arith4`, eingebettet in ein
  Sandwich `fetch -> decode -> [Kern] -> writeback`. Kleine Targets fusionieren mem/wb,
  grosse splitten decode.
- **Wichtig — Stufe ≠ Befehl:** Die 4 Pfeiler existieren *als Pipeline-Stufe* UND *als
  ISA-Befehl*. Es gibt ein 1:1-Mapping — **es sei denn, es gibt es nicht** (Encoding kann
  nicht alles ausdruecken, HW hat nicht alles -> microcoded). Nie blind 1:1 annehmen.
- **Orthogonalitaet:** Basis-Op + Flags/Steuersignale (`inv_1/2/3`, `unsigned`, `op_type`,
  WRF, `cst_table`/`src3_idx`) erzeugen viele Pseudo-Ops aus wenigen Opcodes. ~20 echte
  Opcode-Slots -> >100 High-Level-Ops.

## Datei-Karte

| Datei | Rolle | Stand |
|---|---|---|
| `pipeline.py` | **Kernmodul** (ISS): 4 Stufen, Enums (`ArithMode`, `BitFrobMode`, `TernLut`, `OpType`), CST-Tabellen, `execute_pipeline()`. Import-sauber. | ~1626 Z. |
| `helpers.py` | Gemeinsame ctrl-Dicts (`_b_perm/_b_bitf/_b_tern/_b_arit`) + Mikrocode-Helfer (`gray_to_bin`, `mul16_sqrom`, ...). Importiert `from pipeline import *`. | ~737 Z. |
| `ops.py` | Makro-Op-DSL: `Op(stage, mode, ...)` -> ctrl-Dict. Bruecke zum Decoder. | ~89 Z. |
| `test_pipeline.py` | **Kanonischer Testeinstieg** fuer `pipeline.py`. | ~2787 Z. |
| `fuzz_smt_equivalence.py` | Differential-Fuzzer ISS vs z3 (seeded `random.seed=42`). | ~970 Z. |
| `pipeline_smt.py` | **z3-Beweis-Suite**, Sektionen `M1..M25` als `_run_MX()`, CLI `-g/--group`. Import-sauber (`if __name__` am Ende). | ~3926 Z. |
| `isa_shell.py` | **Rumpf-Pipeline um den Kern**: PC, Register-File, Memory (RAM + MSR), rudimentaerer Decoder fuer die Papier-Encodings. | ~1146 Z. |
| `shell_examples.py` | 15 End-to-End-Algo-Tests gegen `isa_shell.py` (memcpy/strcpy/popcount/unaligned/strlen/FIR/GF-Mul/Binomial/LDI/slogii/cbitfrob_i/Goertzel/BITREV_BAM/FFT-8/CORDIC). Implementiert NIE die Shell, nur konsumiert. | ~764 Z. |
| `shell_planes_diff.py` | Differential: Shell-Planen vs direkter `pipeline`-Aufruf. | ~39 Z. |
| `isa_vision.md` | **Design-Vision** (Sektionen 1-12): Sandwich, RF, Encoding-Entwuerfe, MSR, Atomics, Microcode, Philosophie, DSP-Anwendungsfaelle, harte Funde. | ~651 Z. |
| `ops_survey.md` | **Op-Bestand**: was da ist, was frei ist, was Microcode ist, LUT-Schaetzung. | ~370 Z. |

Kein Git-Subrepo hier; Teil von `requi` (branch `master`).
Mehrere Dateien haben hartkodierte `sys.path.insert(0, .../pipeline_ops)`.

## Tests / Laeufe

```bash
python test_pipeline.py                 # alle Kernel-Tests
python test_pipeline.py <substring>     # gefiltert
python test_pipeline.py --list          # Testnamen
python shell_examples.py                # ISA-Shell Algo-Tests (exit 0 <=> PASS)
python shell_planes_diff.py             # Shell<->Kern Differential
python fuzz_smt_equivalence.py          # Fuzzer (0 Mismatches erwartet)
python pipeline_smt.py                  # ganze SMT-Suite
python pipeline_smt.py -g <alias>       # gezielte Sektion (gegen Context/Timeouts!)
python pipeline_smt.py --list           # Sektionen + Aliase
python pipeline_smt.py --skip M15
```

`pipeline_smt.py`-Aliase: `ternlog`(M1) `bitfrob`(M2-M7,M16-M18) `arith4`(M8,M8b)
`permb`(M9) `pipe`(M10,M10b) `macro`(M12-M14) `gf`(M15) `decoder`(M19) `sqrom`(M20)
`div`(M21) `newton32`(M22) `offset`(M23) `bcond`(M24) `f1imm`(M25) `smoke`(M1-M4,M8b).

**Nach jeder Aenderung gruen sehen:** `test_pipeline.py`, `shell_examples.py`,
`fuzz_smt_equivalence.py`. Shell-Aenderungen zusaetzlich `run_smoke()`.

## Kanonische Doku (wo wartet was)

- **Encoding-Entwuerfe** (Papier, nicht final): `isa_vision.md` Sektion 3 — F3/F2/F1/FMEM/LDI-Formen,
  Feld-Rotation, S-Cousins, Control-Op, Memory-Plane.
- **Register-File:** Sektion 2. **MSR:** 4. **Atomics:** 5. **Microcode-Ebenen:** 6.
  **Pflichten:** 7. **Meta-Lektionen:** 8. **Hardware-Targets:** 10.
- **Shell-Realitaet + alle harten Funde:** `isa_vision.md` Sektion 11.
- **DSP-/Signal-Anwendungsfaelle** (Goertzel/FFT-8/CORDIC + ISA-Ideen): Sektion 12.
- **Frei/belegt/Microcode je Op:** `ops_survey.md`.

## Konventionen & Fallen (das, was Agenten sonst falsch annehmen)

**Register-Encoding:**
- `dst` ist **global 5 Bit**: C0-C15 = Slots 0-15, S0-S15 = Slots 16-31.
- `src`-Felder sind **gruppenrelativ 4 Bit** (C-Gruppe bzw. S-Gruppe getrennt).
- Zwei Zero-Register: C0 und S0 (lesen 0, Schreiben ins Nirvana).
- **Verwechslung C/S ist der haeufigste Fehler** (z.B. `dst=1` = C1, nicht S1 -> `dst=17`).

**CMP-Semantik (ueberraschend):** Per-Lane-Gleichheits-Maske.
`res = 0xFFFFFFFF` (FLAG_S) wenn **gleich**, `res = 0` (FLAG_Z) wenn **ungleich**.
Also `bxx_eq` / FLAG_S = "branch wenn gleich".

**Control / Branches:**
- `bxx` ist **rein PC-relativ**; `src1`/`src2` sind dort Bedingungs-Encoding (XOR-Substitution).
- `bra`/`brl` nutzen Register-Basis/Index (fuer Tabellenspruenge).
- **Offset-Einheit = 2 Byte (Halbwort) × scale** (`offs * 2 * scale`).

**Limits:**
- Fine-Shift nur 0..7 (`s3 & 7`); Voll-Shifts (0..31) via `permb`/`cbitfrob_i`.
- `sarithi` Imm13: `val(9, sign-ext) << shift(4)`.
- LDI-MASK-Muster: Element-Periode beachten (8-Bit-Element mit 8 Einsen = 0xFFFFFFFF).

**Konstanten-Pool:** nur nicht-konstruierbare Basiswerte. Negationen brauchen keinen
eigenen Eintrag (Eingangs-Negierer); Muster (`0x0F..`, `0x01..`) via ternlog/bitfrob/LDI.
bitfrob-Shift-**Amount**-Modi duerfen den Pool nicht nutzen (wuerde Amount ueberschreiben).

**z3-Fallen (erprobt, `pipeline_smt.py` / `fuzz_*`):**
- z3py hat **kein `SDiv`/`SRem`** (nur UDiv/URem) -> signed per Abs/Vorzeichen bauen.
- `BVneg` unzuverlaessig -> `bvsub(0, x)`.
- **Kein `SGT`/`SLT`** -> Vorzeichen-Flip + UGT/ULT.
- **BV-Mul erhaelt Breite** -> vorher `ZeroExt`.
- Python-`int` in `z3.If` braucht `BitVecVal`.
- `parallel.enable=True` toetet leichte Faelle (vorbestehend) -> M13-Q65/Q69 "unknown".
- pyright-Meldungen (`as_long`, `&`,`|`,`^`,`~` auf z3-Exprs) sind **Falschalarme**.

**Arbeitsweise:**
- **Beweis schlaegt Popularitaet.** LLM-Bias (x86-Idiome, unaligned-Load-Tricks) vermeiden;
  seltene-elegante Wege (AltiVec-Denken) pruefen, statt Korpus-Haeufigkeit zu folgen.
  Entscheidet der Fuzzer/SAT, nicht die Trainingsdaten.
- Harness-Dateien (`shell_examples.py`, `shell_planes_diff.py`) sind **read-only** fuer Tests.
- Grosse SMT-Laeufe nur per `-g <alias>` (Context/Timeout).
- Subagenten (cavecrew): `cavecrew-builder` fuer ≤2-Datei-Edits, `cavecrew-investigator`
  zum Lokalisieren. 3+ Dateien -> Main-Thread oder Split.
- Aenderungen an `pipeline.py` (Kern) immer gegen `test_pipeline.py` + Fuzzer verifizieren —
  ein Kern-Fix kann still Semantik verschieben (z.B. Flags bei Carry-Overflow).

## Offene Kandidaten (Stand)

- Packed-Lane-Size-Feld fehlt im Encoding (F3-ctrl voll) — Plane-Split / Bit-Klau / Cousine.
- `sbitfrob_i` / `sshufb_i` (i-Suffix-Immediate-Cousins) noch nicht gebaut.
- SMT-M13-Q65/Q69 `unknown -> STOP` (vorbestehend, parallel.enable-Killer).
- Weitere Beispiel-Algos (Fibonacci, ...), Seiten/User-Superuser-Split fuer writable MSR.
- Backends (gcc/LLVM) anpassen + Tracing, sobald die ISA stabiler ist (dynamische
  Op-Haeufigkeit >> statische).
