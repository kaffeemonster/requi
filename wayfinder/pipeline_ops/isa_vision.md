# ISA-Vision — Design-Notizen

> Work-in-progress-Notizen aus den Architektur-Gesprächen.
> Keine fertige Spezifikation. Encoding-Beispiele sind Papier-Entwürfe.
> "Inkohärentes Gebrabbel" → konserviert, damit es nicht mehr so leicht verloren geht.
> Historien-Referenz: pipeline.py (ISS), pipeline_smt.py (Z3-Suite), test_pipeline.py, fuzz_smt_equivalence.py, helpers.py, ops_survey.md

---

## 1. Pipeline-Sandwich: Kern + Peripherie

```
fetch → decode → [permb → bitfrob → ternlog → arith4] → mem/writeback
```

- Die **4 Kern-Stufen** sind eingebettet in das übliche Sandwich aus fetch/decode/mem/writeback.
- **Kern skaliert nicht** — er bleibt stabil. Die Peripherie skaliert nach Target.

### Skalierung nach Target
- **Kleine Targets (Tang Nano 9K):** mem + writeback fusionieren → 1 Stufe. Weniger Pipeline-Register, weniger LUT.
- **Große Targets (XC7K480T):** writeback/mem splitten; ggf. **decode in 2 Stufen** aufteilen (pre-decode/fetch-decode), um Timing-Slacks stabil zu kriegen.

### Die 4 Pfeiler sind Stufe UND Befehl — Achtung, verwirrend!
```
PERMB / BITFROB / TERNLOG / ARITH4
  ├─ als ISA-BEFEHL      (viele Pseudo-Ops = syntaktischer Zucker, zeigen hierher)
  └─ als PIPELINE-STUFE  (physikalische Einheit)
```
- Befehl und Stufe können sich in **Semantik/Fähigkeit unterscheiden**:
  - Encoding kann nicht alles ausdrücken
  - HW hat nicht alles → wird microcoded
- **Für Analyse immer dreiteilen:** (a) Stufe (fixe Rechensinheit), (b) ISA-Befehl (Abstraktion), (c) Mapping dazwischen (encoding-/HW-abhängig).
- Es gibt ein 1:1-Mapping — *es sei denn, es gibt es nicht.*

---

## 2. Register-File: C/S-Gruppen

- **32 logische Register** in **zwei Gruppen**:
  - **C0-C15 ("complex", M68k-Datenregister)**: nur hier kommen **3 Operanden** her. Read-Port-Verdrahtung (3 Ports) braucht nur diese Gruppe.
  - **S0-S15 ("simple", M68k-Adressregister)**: **nur 2 Operanden** — s3 ist oft 0 oder eine Konstante. Pointer, Zähler, Adressen.
- **Schreiben:** alle Instruktionen schreiben wahlfrei in alle 32 (DST = 5 Bit, global).
- **Lesen:** nur aus der eigenen Gruppe (durch den Opcode deklariert).
- **C0 = Zero-Reg, S0 = Zero-Reg:** lesen immer 0, Schreiben geht ins Nirvana.
  - **Zwei** Zero-Register, weil die src-Felder **4 Bit gruppenrelativ** sind — jede Gruppe braucht ihren eigenen Index 0. Anders nicht binär encodierbar.
- **Decoder-Freiheit:** Der Decoder darf machen, was er will (großes Target: Register-Renaming) — bleibt aber sinnvoll in den gleichen Constraints, weil HW-Realität in die ISA leakt (Read-Port-Netzwerke sind teuer). Leck akzeptiert, *schulterzuck*.
- **Falsch-Gruppen-Lesen existiert nicht:** "ich bin sarith" → src-Felder liegen in der S-Gruppe.
- **Kleines Target:** RF-Read kann multi-takt-multiplexen (Time-Division, RF doppelte Frequenz — wie das Kern-Pipeline-Konzept). Target-Detail.
- **Guardrail:** keine crazy Instructionen bauen, die 7 Reads + 4 Writes brauchen. ISS muss das nicht berücksichtigen (bekommt Werte).

---

## 3. Encoding: Fixed-Size 32 Bit

- **32 Bit fixed size. Ja, das wird eng.** Grund, warum vom Opcode-Malen zum ISS gewechselt wurde: herausfinden, **wieviel Bits wohin** gehören.
- **Bit 0 = compressed:** Escape-Hatch für **16-bit-Encoding** (\*viel Runtime-Code sind einfache Ops, keine Multi-Operand-Monster).
- **WRF-Bit** (write_read_flags): steuert, ob Flags erzeugt werden (klassische ALU-Ops, egal C oder S) oder ob "darauf" gehört wird.
- **Little-Endian** konvention. **Kein Bi-Endian** (baut einen `bswap` ein — Bi-Endian ist Unsinn). "Logisch" fängt die Op oben an, im Speicher steht compressed am Anfang (Feld- vs Byte-Ordnung getrennt denken).
- **Ziel: Register-Felder einheitlich über alle Befehle** — feste Positionen → Decoder einfach. Beispiel-Gedanke: dst an der 16/32-Grenze, src1 in den ersten 16 Bit. Wird noch umgeschuffelt.
- **Plane-Modell:** opcode 4 Bit = **16 Op-Planes**. Die großen 4 (permb/bitfrob/ternlog/arith4) belegen je eine ganze Plane und decken den Großteil ab; jede Plane interpretiert die restlichen Felder eigentümlich.

### Beispiel-Entwurf (PAPIER, NICHT final) — ternlog

```c
struct ISAOpTernlog {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane
  Uint32_t csrc3: 4;           // 25-22  C-Gruppe (Rotation: src3 oben)
  Uint32_t dst: 5;             // 21-17  alle 32 schreibbar
  Uint32_t csrc1: 4;           // 16-13  C-Gruppe
  Uint32_t csrc2: 4;           // 12-9   C-Gruppe
  Uint32_t cst_pool_flag: 1;   // 8      src3 → Konstanten-Pool
  Uint32_t imm8: 8;            // 7-0    ternlog-LUT! volle 256
};
```

- **imm8 exponiert die vollen 256 TernLut-Werte** — nicht nur die 29 benannten Mnemonics.
- cst_pool_flag = der `cst_table`/`src3_idx`-Mechanismus im Encoding: 3. Operand kommt aus dem Konstanten-Pool statt einem Register ("s3 ist oft 0/Konstante").

### Beispiel-Entwurf (PAPIER, NICHT final) — permb, Variante A (original)

```c
struct ISAOpPermb_A {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane
  Uint32_t csrc3: 4;           // 25-22  C-Gruppe (Rotation)
  Uint32_t dst: 5;             // 21-17
  Uint32_t csrc1: 4;           // 16-13  C-Gruppe
  Uint32_t csrc2: 4;           // 12-9   C-Gruppe
  Uint32_t cst_pool_flag: 1;   // 8      src3 → Konstanten-Pool
  Uint32_t nibble_mode: 1;     // 7      Indizes pro Nibble, nicht Byte
  Uint32_t blank_mode: 1;      // 6      Lane-High-Bit → Lane ausblenden
  Uint32_t shift_mode: 1;      // 5      Shift-Modus, src3 low-Bits = Amount
  Uint32_t right_left: 1;      // 4      Rechts oder Links
  Uint32_t mode: 4;            // 3-0    permb-Modus
};
```

### Beispiel-Entwurf (PAPIER, NICHT final) — permb, Variante B (Empfehlung)

Die Shift-Steuerung (Varianten-Kommentare oben: `shift_mode`/`right_left`) wandert **in ein einziges `mode`-Feld**, statt eigener Bool-Bits. `blank` bleibt orthogonal (Lane ausblenden ist in jedem Modus sinnvoll).

```c
struct ISAOpPermb_B {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane
  Uint32_t csrc3: 4;           // 25-22  C-Gruppe (Rotation)
  Uint32_t dst: 5;             // 21-17
  Uint32_t csrc1: 4;           // 16-13  C-Gruppe
  Uint32_t csrc2: 4;           // 12-9   C-Gruppe
  Uint32_t cst_pool_flag: 1;   // 8      src3 → Konstanten-Pool
  Uint32_t blank_mode: 1;      // 7      Lane-High-Bit → Lane ausblenden
  Uint32_t pad: 3;             // 6-4    frei (Feldverteilung noch offen)
  Uint32_t mode: 4;            // 3-0    permb-Modus
};
```

- **mode: 4 (nicht 2)**: mit 2 Bit fehlen die Nibble×Shift-Direktions-Kombinationen (byte-shift-l, byte-shift-r, nibble-shift-l, nibble-shift-r = 4, ohne die Vektor-Modi). Ein Feld (16 mögliche Modi) ist decoder-freundlicher als 3 Bool-Bits (Tabelle statt Bool-Matrix), erweiterbar — Schule wie ternlog-imm8.
- **Shift-Amount** aus `csrc3` (regulärer Operand); `cst_pool_flag` bleibt orthogonal (Amount darf auch Konstante sein).

### Beispiel-Entwurf (PAPIER, NICHT final) — bitfrob

```c
struct ISAOpBitfrob {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane
  Uint32_t csrc3: 4;           // 25-22  C-Gruppe (Rotation)
  Uint32_t dst: 5;             // 21-17
  Uint32_t csrc1: 4;           // 16-13  C-Gruppe
  Uint32_t csrc2: 4;           // 12-9   C-Gruppe
  Uint32_t cst_pool_flag: 1;   // 8      src3 → Konstanten-Pool (ja, sinnvoll)
  Uint32_t inv_src1: 1;        // 7      !src1
  Uint32_t inv_src2: 1;        // 6      !src2
  Uint32_t inv_src3: 1;        // 5      !src3
  Uint32_t mode: 5;            // 4-0    bitfrob-Modus (31 Modi im ISS — randvoll)
};
```

- **cst_pool_flag JA** — bitfrob-Modi tragen häufig konstant-artige Operanden (pext/pdep-Maske, Shift-Amount, POLY_RED-Index): Pool spart Register + Load. Feste Lage (Bit 8) wie ternlog/permb = einheitliche Feldposition über Planes.
- `inv_src1/2/3` = exakt die bitfrob-inv-Bits aus dem ISS (orthogonale Invertierbarkeit, anders als ternlog).
- Summe: 1+1+4+5+4+4+4+1+1+1+1+5 = **32 ✓**
- **mode:5 = randvoll** (31 ISS-Modi) — **LÖSUNG: Helper-Aussortierung, siehe nächste Notiz.**

### bitfrob: User-facing vs interne Helper + 2-Op-Split (Klassifikation)

**Grundprinzip: ISA = API, kein Pipeline-Fußabdruck.** Die Pipeline kann alle 33 bitfrob-Modi (LSR=0 … PDEP_N=32, pipeline.py:93-126) mit 3 Slots ausdrücken — die ISA exponiert nur, was sinnvoll ist; der Rest bleibt **intern** (Decoder/Mikrocode, wie SQROM8 bei arith: Export = MUL/DIV). "Intern reich, ISA kuratiert."

**Struktur (User-Entscheidung):**
```
bitfrob     = 3-Op-Plane, NUR Modi, die mit 3 Operanden Sinn machen
              (Long-Shift lo+hi+Amount, BITSWAP Maske+Shift, …)
cbitfrob    = 2-Op-Ops mit C-Quellen    ┐
sbitfrob    = 2-Op-Ops mit S-Quellen    ┴ in EINER Sub-Split-Plane
cbitfrobi   = src2 fällt weg → +4 Bit Imm  ┐
sbitfrobi   = dito                         ┴ i-Suffix-Versionen
```

- **2-Op-Ops lesen C-Daten direkt (cbitfrob)** — kein MOV-Umweg nötig (z.B. LZC auf C-Register).
- **Read-Port-Ersparnis bleibt:** 2-Op = nur 2 Ports (S kann auf 2 Ports bleiben; C hat 3, nutzt bei 2-Op nur 2).
- **Intern (Helper, >0x1F-Konvention wie MFC=40):** NIBLKP (S-Box-Lookup, steckt in mul16_sqrom-Mikrocode), POLY_RED (Poly-Tabelle, "intern reich, ISA dünn"), CLMUL_LO/HI (GF-Mul-Bausteine; Export wäre `GFMUL`), BMAT_N_OR/XOR ("Baustein für Full-BMM via Microcode"), SHR_STICKY (Float-Rounding-Helper, aux-Semantik).
- **User-facing 2-Op-Kandidaten (c/sbitfrob):** LSR/LSL/ROR/ASR/ROL/SEXT (Amount via src2 oder imm), LZC, TZC, POPCNT_B/N, PARITY_B/W, LOG2, LOG10, BITREV8, BITZIP_8/UNZIP_8, MASK/MASKW, PEXT_N/PDEP_N, BMATOR/XOR, BCD_HC, GFNI_AFFINE.
- **3-Op-Kandidaten (bitfrob-Plane):** Long-Shift (neu), BITSWAP — die seltenen echten 3-Slot-Fälle.
- **Lösung "mode:5 randvoll":** 3-Op-Plane hält nur wenige Modi (Luft), 2-Op-Welt lebt in der Sub-Split-Plane mit eigenen Slots + i-Versionen; intern > 0x1F (MFC-Konvention). Enum-Re-Nummerierung = späterer Refactor (wie MFC 12→40, mit Subagent).

### Beispiel-Entwurf (PAPIER, NICHT final) — arith4 (der Knallpunkt)

```c
struct ISAOpArith4 {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane
  Uint32_t csrc3: 4;           // 25-22  C-Gruppe (Rotation)
  Uint32_t dst: 5;             // 21-17
  Uint32_t csrc1: 4;           // 16-13  C-Gruppe
  Uint32_t csrc2: 4;           // 12-9   C-Gruppe
  Uint32_t cst_pool_flag: 1;   // 8      src3 → Konstanten-Pool (entschieden: JA)
  Uint32_t negate_src1: 1;     // 7      ~src1
  Uint32_t negate_src2: 1;     // 6      ~src2
  Uint32_t negate_src3: 1;     // 5      ~src3
  Uint32_t mode: 5;            // 4-0    Arith-Modus
};
```

- **Bit 8-Entscheidung: cst_pool_flag, NICHT high-bit-mode.** Einheitliche Feldlage über alle Planes (Decoder-Ziel) darf nicht pro Plane brechen; Modus-Druck wird durch **mehrere arith4-Planen** entschärft (s.u.); Pool bei arith4 real nutzbar (Akku-Start PSAD, AVG-Rounding, Vergleichs-Masken, MULFMA-Addend).
- **Mehrere arith4-Planen:** `scalar-arith / packed-arith / float-arith` — je eigene Plane, je eigener 5-Bit-Mode-Raum (32 pro Plane; heute 26 belegt in einer). Deckt "packed in allen Breiten" ohne op_type-Verschachtelung pro Mode.
- Falls je >32 Modi in EINER Plane nötig: zweite arith4-Plane, nicht das gemeinsame Layout verbiegen.
- `negate_src1/2/3` = die arith4-inv-Bits aus dem ISS.
- Summe: 1+1+4+5+4+4+4+1+1+1+1+5 = **32 ✓**

### Feld-Rotation (Entscheidung: src3 oben)

Alle vier Register-Felder **rotieren**: `src3` sitzt oben (25-22), darunter `dst` (21-17), `src1` (16-13), `src2` (12-9). Reine Umsortierung — 4+5+4+4 = 17 Bit, **Bit-Kosten 0**.

```
31 C · 30 WRF · 29-26 opcode · 25-22 src3 · 21-17 dst · 16-13 src1 · 12-9 src2 · 8 cst_pool · 7-0 imm/mode
```

**Gewinn:** Befehle ohne src3 (2-Operanden) haben oben **25-22 = 4 freie Bits**:
- **+4 Bit Sub-Opcode** (16 Sub-Ops pro Plane: CLR/DUP/INC-artige Pseudo-Ops ohne eigene Plane)
- **sarith** (S-Pfad, 2 Operanden) hat den Slot **immer** frei → **12-Bit-Immediate** (25-22 + 7-0) = HIMM-Grundgerüst
- Gilt auch für ternlog-2-Op / permb-Shift-Varianten ohne src3

**Erhalten:** `dst`-Lage über Planes einheitlich (21-17), `cst_pool_flag` auf Bit 8, `opcode` auf 29-26 — Decoder-Ziel unversehrt. src3 = "mietfreier Slot" für Opcode-/Immediate-Erweiterung.

### Die 4 S-Cousins (PAPIER, NICHT final) — kollabiert: eine S-Plane, 16 Sub-Befehle

S-Gruppen-Versionen der 4 Pfeiler (M68k-A-Register-Linie): **2 Operanden, kein src3**. **Kollaps:** die ehemaligen src3-Bits (25-22) werden **+4 Opcode-Bits** → eine S-Plane trägt **16 Befehlsslots** statt 4 Cousin-Schubladen.

```
31 C · 30 WRF · 29-26 opcode (S-Plane) · 25-22 subop (16 Slots) · 21-17 dst · 16-13 ssrc1 · 12-9 ssrc2 | imm_hi · 8-0 imm_lo/mode
```

**8 von 16 Sub-Slots belegt, 8 frei:**

| Sub | Register-Form (2-Op) | Sub | Immediate-Form (src2 frei → +4 Bit) |
|---|---|---|---|
| 1 | sarith: ADD, SUB/SBC(inv), CMP, SLT/SLTU, ADDSHIFT1/2 (LEA-artig), INC/DEC, CLR, NEG, MOV | 5 | sarith_imm: ALU + **Imm13** (9+4) — Pointer-Offsets |
| 2 | slogi: ternlog-2-Op, imm4 = 16 Logik-Ops | 6 | slogi_imm: Logik + Imm13-Maske |
| 3 | sbitfrob: LSR/LSL/ASR/Sticky, LZC/TZC/POPCNT (1-Op!), PEXT/PDEP (src2=Maske), UBFX/BFI | 7 | sbitfrob_imm: Shift/Op + Imm13 |
| 4 | sshufb: permb-2-Op, src1=Daten, src2=Lane-Vektor | 8 | sshufb_imm: konstante Perm-Maske |

- **Mode/imm4 wandert nach unten** (in 8-0); die **5 Bit darüber (dst-Region 21-17) — offen, "mal sehen"**.
- **Immediate-Formen:** src2 (12-9) entfällt → **Imm = 13 Bit** (9 + 4).
- Bit 8 (`cst_pool_flag`) bei S-Cousins: offen — der Imm-Raum übernimmt teils die Konstante-Rolle (Notiz).
- Kein MUL/DIV/PSAD im S-Pfad (Multiplikation/Division gehört in die C-Gruppe; Pointer-Pfad rechnet additiv).

### Die magische Control-Op (PAPIER, NICHT final)

```c
struct ISAOpControl {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF
  Uint32_t opcode: 4;          // 29-26  Op-Plane (Control)
  Uint32_t scale: 2;           // 25-24  Offset-Scale (1/2/4/8)
  Uint32_t offset_high: 2;     // 23-22  Offset high (11 Bit signed gesamt)
  Uint32_t dst_mask: 5;        // 21-17  WRF=0: Link (alle 32); WRF=1: Flagmaske
  Uint32_t src1: 4;            // 16-13  S-Gruppe, Base
  Uint32_t src2: 4;            // 12-9   S-Gruppe, Index << scale
  Uint32_t offset_low: 9;      // 8-0    Offset low
};
```

- **Eine Op deckt die ganze Sprung-Welt:** WRF=0 + dst=Link → bra/brl (Branch-and-Link, PC→DST); WRF=1 + dst=Flagmaske → bxx (bedingt); `src1`=PC → PC-relative; `src1`=A-Reg + `src2`=Index → **Register-Offset-Sprung** (Jump-Tabellen).
- **Offset = 11 Bit signed in 2-Byte-Einheiten << scale** → **±2K / ±4K / ±8K / ±16K**. Gewinn gegenüber flachem 13-Bit-Offset (±4K fix): Befehle sind immer gerade ausgerichtet (32-bit UND 16-bit compressed, beide 2-Byte-vielfach) → Bit 0 implizit 0 = 1 Bit geschenkt (M68k/RISC-V-Präzedenz, RISC-V-JAL: 21 Bit in 2-Byte-Einheiten = ±1 MB); Scale-Multiplikator = ARM85-rotated-Geist (Imm<<Shift). **Die 2 geklauten Scale-Bits kommen doppelt zurück.**
- **Plane-JA:** 16 Planes-Budget: 4 Pfeiler + 4 Cousins + Control + Memory + System/MSR + AMOD ≈ 11-13 → Luft bleibt. Control zahlt sich als "eine Op statt Familie" aus.
- **Patente: bedenkenlos.** `Base + Index<<scale + Offset` = M68k `d16(An,Xi)` (1979, prior art); ARM-rotated-imm = original ARM 1985 (längst abgelaufen). Eigene Bit-Kodierung ohnehin → kein Angriffspunkt.
- **Scale-Frage GELÖST:** 2 Bit Scale (25-24) + 11-Bit-Offset in 2-Byte-Einheiten — M68k/RISC-V-Ausrichtungs-Trick macht es zum Netto-Gewinn.
- Summe: 1+1+4+2+2+5+4+4+9 = **32 ✓**

### Die Memory-Plane (PAPIER, NICHT final, temporär)

Control-Layout übernommen. **Scale = Zugriffsbreite** (nicht nur Offset-Skalierung):

```c
struct ISAOpMemory {
  Uint32_t compressed: 1;      // 31  Escape für 16-bit
  Uint32_t write_read_flags: 1;// 30  WRF=0 → Load, WRF=1 → Store
  Uint32_t opcode: 4;          // 29-26  Op-Plane (Memory)
  Uint32_t scale: 2;           // 25-24  Breite: 1=byte, 2=half, 4=word, 8=dword
  Uint32_t offset_high: 2;     // 23-22  Offset high (11 Bit signed gesamt)
  Uint32_t dst: 5;             // 21-17  Load: Ziel (alle 32) / Store: Datenquelle
  Uint32_t src1: 4;            // 16-13  S-Gruppe, Base
  Uint32_t src2: 4;            // 12-9   S-Gruppe, Index (byte-genau, unaligned ok)
  Uint32_t offset_low: 9;      // 8-0    Offset low
};
```

- **WRF = Load/Store-Schalter (entschieden JA):** Loads/Stores setzen klassisch keine Flags → WRF semantisch leer → frei als Richtungs-Bit. Spart 1 Plane; Muster-Konsistenz mit Control.
- **`dst`-Doppelnutzung:** Load → Ziel (alle 32, Schreibregel); Store → Datenquelle (alle 32 — jedes Reg speicherbar). Guardrail: Load = 2 Reads+1 Write+1 Mem-Read; Store = 3 Reads+1 Mem-Write — ok.
- **Offset = 11 Bit signed in Breiten-Einheiten << scale:** byte ±2K, half ±4K, word ±8K, dword ±16K (ARM-LDR-artig: imm12<<2 für Wort-Loads). Gleiche Formel wie Control — Einheit = Zugriffsbreite.
- **Unaligned-Pflicht bleibt:** eingebetteter Offset breiten-skaliert (aligned); **Basis+Index byte-genau** → unaligned via Register-Wege.
- **dword in 32-bit-ISA:** Register-Pair (lo+hi in 2 Regs) — offen, Frage notiert.
- **OFFEN — sign/zero-Erweiterung** bei byte/half-Loads (LB/LBU-Problem): braucht 1 Bit, noch kein Platz. Nicht über-entschieden.
- Summe: 1+1+4+2+2+5+4+4+9 = **32 ✓**

### Op-Arten (arith4 als Beispiel — ISA-Opcode-Struktur)

```
carith #MODE, [flags], cmplx_src1, cmplx_src2, cmplx_src3, dst
sarith #MODE, [flags], smpl_src1,  smpl_src2,             dst
+ große Immediates (weitere Op-Art)
```
- **Kein Cross-Gruppen-Read** vorgesehen (hoffentlich nie nötig).
- sarith (2×4-Bit-Src) spart 4 Bit → Raum für große Immediates (HIMM).

### Eine "Control"-Op statt Befehls-Familie (WRF-Multiplex)

```
WRF=0  + dst=ZeroReg                → bra       (bedingungslos)
WRF=1  + dst=ZeroReg + Flagmaske im src-Feld → bxx  (bedingt)
dst ≠ ZeroReg                       → Branch-and-Link (PC → DST)
```
- Die Flagmaske wählt die Bedingung → bxx, bra, brl aus **einer** Control-Op.
- **System/Trap** schließt sich an: WRF=Hören-Modus + Flagmaske → Trap. Beispiel: `DIV` setzt FLAG_O bei Division durch Null (definiert, kein HW-Trap); wer mag, hängt `Trap!FLAG_O` daran. Per Stelle entscheidbar — Kern zwingt nichts.

### Pseudo-Ops aus dem RISC-Playbook (gelöst)

Wir haben mehr als `or %g0` — die Zero-Register C0/S0 sind Pseudo-Op-Fabrik UND Hint-Raum:

| Pseudo-Op | Encoding | Trick |
|---|---|---|
| `mov dst,src` | ternlog `MOV_A`/`MOV_B` | direkte Kopie (SPARC brauchte `or %g0,src,dst`; wir haben MOV_* im TernLut) |
| `nop` | ternlog `KLAR`, DST=C0, WRF=0 | Ergebnis 0 → Nirvana, keine Flags |
| `pause`/`relax` | `sarith …`, DST=S0, WRF=0 | Hint-Raum (ARMv8-Modell: `nop`=`hint #0`) |

- **Hint-Raum:** jede Op mit **DST ∈ Zero-Reg + WRF=0** = Hint-Gehäuse. Alte HW: NOP; neue HW interpretiert dokumentierte Muster (`sarith ADD,S0,S0` = pause, Variante = relax, später WFE-artige) als Zustandshinweis. → HW-Evolution ohne ISA-Änderung, gleiche Binary überall.
- **Grenze:** nicht jede Wegwerf-Rechnung ist offizieller Hint — die Doku listet die Vertrags-Hints; alles andere bleibt NOP. Decoder-Freiheit ja, aber dokumentiert.

---

## 4. MSR-Raum / loadmsr / writemsr

- Idee: MSR-Raum, **für jeden lesbar** (nicht Ring-0-privilegiert — Anti-PPC/SPARC/MIPS, die stecken das in ein nur-Ring0-lesbares Processor Status Word).
- **Öffentlich lesbar sollen sein:** PC (PC-relative Adressierung), FLAGS, ein **cycle-counter**, IDENT/Feature-Register (falls ggf. Erweiterungsflags; dynamischer Dispatch: "hast du Altivec?", "Popcnt-Implementierung gut?").
- **writemsr** wird technisch nötig (OS-Spezialkram: Task-ID, Process-Page-Table-Root-Pointer, …).
- **Faltung in ld/st:** MSR = **pseudo-memory-mapped IO** im Adressraum — eine reservierte "nicht echte" Region. CPU fängt die Adresse ab und biegt auf MSR-Register/ROM um. Also **kein eigener loadmsr-opcode**, alles ist ld/st. HW-Notiz: die Region muss vor Cache/L2 abgefangen werden.
- **Konstanten-Whopper:** In Instruktionen sind nur **16 Konstanten** ansprechbar (ARITH_CST/cst_table), aber der MSR-Weg kann das **ganze ISA-Konstanten-ROM** öffnen ("warum ein Geheimnis daraus machen, außer hochgradig Proprietäres? Lass den User mit ternlog die Bitfrob-Konstanten nutzen — warum verbauen?").
- **Decoder-intern ≠ User-Zugriff (Schichtung):** Intern braucht der Decoder viele Konstanten (BITFROB_CST, POLY_RED-ROM, evtl. Reziprok-ROM/Newton) — **aber das ist Implementierungs-Detail**. Der User spricht die Poly-Tabelle nie selbst an; **ein in der ISA ausgewählter Mode** wählt intern die passende Konstante (`cst_table`/`src3_idx`-Slot). User-Sicht: `#MODE + optional 1/16-Pool-Index`, nicht "ROM-Zelle 0x11B". → **Kein doppeltes Konstanten-Immediate im Encoding nötig**: intern reich, ISA dünn = Feature (weniger Bits, klarer Modus). Der MSR-ROM-Zugriff bleibt öffentlich, aber exotisch (Nicht-Alltagspfad).
- **Konstanten-Direktzugriff bleibt in den Ops** (cst_table/src3_idx) — das ist der Schnellpfad, ohne ld, ohne Register-Allokation.
- **Preis der Offenheit:** Konstanten werden Teil der öffentlichen API → müssen in **jedem** Chip dieser ISA eingebaut sein (ROM-Pflicht).
- `cst_table`/`src3_idx` siehe pipeline.py (ARITH_CST ~Zeile 1069, NIBLKP ~Zeile 81).

---

## 5. Atomic Ops — Basis-Pflicht

- **Atomic gehört in die Basis** (kein Extension-Zusatz).
- **µC-/single-core-Weg:** Interrupt-Sperre am Kern: *Interrupts aus → laden → (ternlog/arith4) → write → Interrupts an.* Der Kern hat alles für einen Read-Modify-Write. Beispiel: atomares XNOR einfach so.
- **Dichtes-Target-Weg ("gute" atomics):** Aufgaben gehen an den Cache-Controller/Memory-Subsystem, der Kern ist da eh raus.
- **AMOD-Muster (bevorzugt):**
  ```
  AMOD #op, addr, dst        # load → ternlog/arith4 → store, atomar
  op ∈ { swap, cas, add, sub, inc, dec, max, min, and, or, xor, xnor, ... }
  ```
  Ein Op mit Operator-Immediate deckt die kurze Liste (CAS, inc/dec, add/sub, evtl. swap) + alles, was die Kern-Ops hergeben.
  - µC: Interrupt-Sperre; dick: Subsystem-AMO/CAS.
- **LL/SC (Swiss-Army-Knife):** nur Scaffolding, "was du drin machst ist dein Bier" (z.B. doppelt-verkettete Liste atomar). Aber **fehlerfrei bekommt es kaum jemand hin**; real entnimmt man dem Messer immer nur CAS/incdec/addsub/swap. **Und:** Reserve wird durch Interrupt/Context-Switch invalidiert — in interruptreichen kleinen Targets unangenehm. → **Zurückstellen, erst bei echtem SMP.**
- **Interrupt-Sperre reicht nicht immer:** gegen echte SMP/RAM-Sharing braucht man Store-Lock/Reserve im Memory-Subsystem. → Gleiche ISA, zwei Implementierungen (API-Prinzip).
- **Knackpunkt lange Ops / Makro-Micro-Ops:** `MOVEM` kann mitten drin eine Access-Violation auslösen. Drei Konzepte sauber trennen: **Atomizität** / **Preemption** / **Fault**. Lösungsfamilien: Restart-Semantik (M68k-artig), Resume-Punkt, Abort + Partial-Writeback.

---

## 6. Microcode-Ebenen (zwei)

```
┌─ Makro-Microcode (übergeordnet) ────────────────────────────┐
│  Decoder + MEM/WB kommen zum Zug                            │
│  multi-Writeback (z.B. load-with-postincrement: 2 Regs),    │
│  float & co (zu komplex für innere Ebene)                   │
│  ┌─ Microcode (innerste) ───────────────────────────────┐   │
│  │  Sequenzer + ROM: hält den REST an,                  │   │
│  │  looped NUR über die 4 Kern-Stufen:                  │   │
│  │  permb→bitfrob→ternlog→arith4 rattern                │   │
│  └──────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────┘
```
- Innere Ebene = reine Daten-Transformation über die 4 Stufen (z.B. `mul16_sqrom` in helpers.py).
- Makro-Ebene = Instruktions-Abwicklung außerhalb des Kerns; tritt aus dem Kern heraus.
- Erste Anwärter: **MOVEM-Klassiker** (load/store multiple mit predecrement/postincrement) für Stack-Aufbau/-Abbau/Frame-Handling. **push/pop sind nur Mnemonics.**

---

## 7. Pipeline-/Befehlseigenschaften (Pflichten)

- **Unaligned Load = HW-Pflicht.** Muss keine Rekorde aufstellen, aber auch nicht zu wage zur Geschwindigkeit sein. Keine Ausrede für den Implementer — er hat eh eine permb-Stufe; wer unaligned *schnell* will, kann eine manuelle Shuffle-Pipeline aufsetzen.
- **ternlog = volle 256 LUT-Werte** exponierbar (imm8), 29 benannte Member sind Mnemonik, nicht Limit.
- **Dynamic-Lane-Permutation mit Register-Maske** (`permb`) = Pflicht-Basis: unsere Antwort auf Intels jahrzehntelangen `vec_perm`-Mangel und die vpshufb-hi/lo-Lane-Split-Krücke. Maske lebt im Register, kein Cache-Cold-Fetch, keine hardcodierten Shift-Amounts (kein palignr-Fehler).
- **Masken sind normale Daten / normale Register** (keine eigene Mask-Register-Klasse wie AVX-512, die beim Task-Switch gesichert/restored werden muss).
- **Feature-Flags: bewusst GROB.** Kein feines RISC-V-Erweiterungsgefrickel. Basis enthält eine Menge; große Flags nur für echte Extensions (z.B. Vector). Wer nach unten skaliert → **E(mbedded)/lite-Release, da wird die Säge angesetzt** (ganze Bundles raus, keine Einzelflags).

---

## 8. Design-Philosophie (Meta-Lektionen)

- **"Der Compiler wird's fixen" = widerlegt** (Alpha, Itanium/VLIW, auch LLVM-Ausreißer wie fehlendes Bounds-Check-Hoisting). Komplexität in HW legen ist oft billiger als eine SW-Friktion, die der Compiler nie löst (Atomic, Kohärenz, Byte-Zugriff, Datenform-Crossbar).
- **Kein HW-Detail in die ISA leaken:** Branch-Delay-Slot = das Musterverbrechen; Itanium-Stop-Bits = dasselbe Gesicht (und der Hazard-Marker am **Producer** statt **Consumer** macht es schlimmer). Unsere ISA: strikt in-order, keine Scheduling-Bits.
- **Es gibt gute Ideen und schlechte Ideen** — nicht "RISC gut / CISC schlecht". Beides lieferte beides.
- **Intent ist wertvoll:** REP-artige/Block-Ops, die dem Programmierer erlauben, Absicht auszudrücken; unsere Makro-Mikrocode-Ebene liefert das (MOVEM, AMOD, masked-pattern).
- **Basis voll statt spartanisch:** viele der Ops kosten "nichts" (ternlog 64-bit ≈ 68 LUT in Gowin; ein Power-On-Reset-Schaltkreis ≈ 70 LUT!). Die "zu teuer!"-Front ist meist off-base. Reiche ISA, Absägen passiert am Extra-Tisch (E/lite).
- **HW = API.** Software gegen die API; "wie wer was gießt, egal, hauptsache API-konform". Das bestimmt auch die Atomic-/MSR-Dual-Implementierungen.
- **LLM-Bias:** LLMs reproduzieren häufige Idiome (x86-Idiome, unaligned-Load-Tricks) statt selten geschriebener eleganter Wege (AltiVec-Denken). → Bei uns entscheidet **Beweis (ISS/Fuzzer/SMT)**, nicht Trainingsdaten-Popularität. "Nicht 10000× gesehen, sondern einmal bewiesen."

### Op-Abdeckungs-Bilanz (Papier-Zählung, grobe Hausnummer)

High-Level-Mnemonics, die allein aus den 4 Pfeiler-Planen fließen (keine inv/unsigned/op_type-Kombinationen mitgezählt):

| Pfeiler | Ops | Beispiel-Auszug |
|---|---|---|
| arith4 | ~30 | ADD, ADDC, SUBB(SBC), AVG, SATADD, USATADD, CMP, DIV, SLT, SLTU, ABSADD, ADDSHIFT1/2, PMIN, PMAX, PSADD, PSSUB, PSAD, PMUL16, MUL16, MULADD, MUL32(U), MULHI(U), MULFMA, MULFMS, MAC(MUL32ACC), PADD64, SQROM8 |
| ternlog | 29 | AND…MANDN + alle Komplemente, MAJ/MIN, XOR3/XNOR3, SELECT_*, MOV_* |
| bitfrob | 31 | Shifts/Sticky, ROR/ROL, PEXT/PDEP, LZC/TZC/POPCNT, UBFX/BFI, NIBLKP, BMAT*-Familie, POLY_RED |
| permb | ~3 | Byte-Perm, Nibble-Perm, Shift-L/R |

→ **≈90–95 Ops aus den 4 Planes**; plus Peripherie (Control: bra/bxx/brl = 1; Memory: ld/st unaligned, MOVEM, AMOD; MSR) → **≈110–120 total**.

**Die Kern-Bilanz:** ~20 echte Opcode-Slots → >100 High-Level-Ops. Orthogonalität (inv/unsigned/op_type/WRF/Pool) multipliziert die Basis-Ops um Faktor 5–6 — Reichhaltigkeit aus Steuersignalen, nicht aus Opcode-Bergen.

**Vergleichswerte (große Hausnummern, nachzuprüfen):**

| Arch | Mnemonics (ca.) |
|---|---|
| 6502 | ~56 (65C02 ~95) |
| Z80 | ~158 Basis (mit Adressierungs-Kombos ~700) |
| M68k | ~50–60 Basis + Adressierungsarten explodierend |
| MIPS | ~100–150 |
| RISC-V | RV32I ~50–60; RV32IMAFDC ~100–120 |
| ARMv8-A | ~350–500 |
| x86 modern | ~1500+ (flach, kein Orthogonalitäts-Faktor) |

Wir erreichen die Reichhaltigkeit eines ARMv8 mit einem Bruchteil der Decoder-Tabelle — weil die Kombinationen aus Steuersignalen fließen, nicht aus flachen Opcodes.

### Hausaufgabe: OS-Kernel-Befehls-Katalog (offen, Vergleichsgruppen-Tabellen)

Die Pfeiler decken arithmetisch/logisch/bitfrob/byteshuffle ab. Was **außerhalb** davon liegt — die "komischen" Befehle, die ein OS-Kernel braucht — ist noch nicht katalogisiert (dort weniger bewandert, Hausaufgaben-Kopieren nötig):

- **Memory-Ordnung/Sync:** Fence/Barrier (x86 `mfence/lfence`, ARM `DMB/DSB`, RISC-V `fence`), `ISB`-artige Pipe-Synchronisation
- **Privileg/System-Transfer:** `mrs/msr`, RISC-V `csrr*`, x86 `sidt/lidt`-artige, `srs`/System-Register-Swap (unser MSR-Weg deckt das — aber op-Set prüfen)
- **MMU/TLB-Pflege:** `tlbi`/`invlpg`, PTE-Pflege-Helfer, Cache-Ops (`icbi`, `dc zva`, x86 `clflush`/`prefetch`-Familie)
- **Interrupt/Context:** Enable/Disable (`cps`, `ei/di`), Exception-Return (`eret`/`rfe`), Context-ID/Task-ID-Handling (in unserem MSR-Raum vorgesehen), Trap-Entry/Exit-Sequenzen
- **PC-relative/Adressen:** PC-Holen (unser loadmsr-PC), TLS-Helfer, Stack-Bound-Check
- **Power/Hint:** `WFI/WFE`-artige, `nop`, Alignment-Hints
- **Rest:** Sign/Zero-Extend-Helfer (wir haben via SLT/inv/op_type), Endianness (wir: bswap/Spiegel), Saturate/Clamp-Edge-Fälle, BCD-artiges Zeug

Für jede Gruppe eine Vergleichs-Tabelle anlegen (x86 / ARM / RISC-V / M68k / PPC / SPARC / MIPS): was existiert wo, wie teuer, brauchen wir es, in welche Ebene (Basis/Pfeiler/Peripherie/MSR). → Offener Arbeitstitel: `kernel_ops_survey.md`.

---

## 9. Zukunftsausblick: Backends + Tracing

- **Große Backends anpassen** (binutils/gcc/LLVM), sobald weit genug — große Codebasen durchschieben und sehen, was generiert wird:
  1. Welche Instruktionen häufig vorkommen → wo sich **compressed 16-bit** lohnt
  2. Was häufige Konstanten sind → Konstanten-Pool/ROM gestalten
  3. (Sahne, weit gedacht) **Tracing-Implementierung** auf echter HW (Xilinx-Beschleuniger oder Tang Primer 25K): Ausführen statt nur Zählen
  - Alternativ Bochs-artige instrumentierende Emulation als Zwischenstufe.
- **Dynamische Ausführungs-Häufigkeit (wie oft gelaufen) ist erheblich interessanter als statische (wie oft vorkommen).**
- Das **ISS (pipeline.py)** kann die Bochs-artige Ebene heute schon liefern (Op-/Ein-Zähler) → Design-Entscheidungen (compressed, Konstanten) mit Messdaten.

---

## 10. Hardware-Targets

| Target | LUT | DSP | BSRAM | Rolle |
|---|---|---|---|---|
| Tang Nano 9K (GW1NR-9) | ~8.6K | 16 × 18×18 | 468 Kbit | klein, µC-artig |
| **Tang Primer 25K (GW5A-LV25MG121)** | 23,040 LUT4 | 28 | 1,008 Kbit (56 BSRAM) + 180 Kbit SSRAM + 6 PLL, 16+16 Clocks | mittel, **Experimentierboard**, SDRAM-Modul (~32 MB) für Memory/Trace |
| XC7K480T (Baidu-AI-Beschleuniger Ära ~2016) | ~477K | 1920 DSP48E1 | groß | dick; **~4 GB DDR** auf der Karte |

- Trace-Impl-Fähigkeit skaliert mit dem Speicher: Primer + SDRAM = Trace-Puffer im DRAM; Xilinx + 4 GB DDR = kompletter Trace ohne Budget-Sorgen.

---

## 11. ISA-Shell (isa_shell.py) — erste Decoder-Realitaet + Funde

Rumpf-Pipeline um den Kern: PC + RF (C/S-Gruppen, Zero-Regs) + RAM 64K + MSR-pseudo-MMIO (Vektor an 0x0, IDENT/FLAGS/PC/CYCLE) + Decoder fuer die Papier-Formen. Kern-Aufruf: `execute_pipeline` mit arith4-rechnend (prev_in_strobe=0), 3 Stufen bypass (`prev_in_strobe=8`, helpers.py-Muster). Assembler-Helper `carith_w/sarith_w/sarithi_w/ctrl_w/mem_w` bauen 32-Bit-Woerter aus den Lexikon-Formen. Smoke-Programm (Summe 1..10 via ld/carith/sarith/CMP/bxx/bra/st): **PASS**, 76 Instruktionen, op_counts = erster Trace-Zaehler.

**Funde (Encoding-Design-Fragen, die der Smoke aufgedeckt hat):**

1. **F1/sarithi hat KEIN Mode-Feld** — Sub-Op+dst+src1+Imm13 fuellen 32 Bit komplett. Iteration 1: sarithi = ADD-only (Immediate-Cousin primär additiv). Aufloesung offen: Mode in Sub-Op-Slots (mehr Slots je Mode) oder ins Imm-Feld. **Loesungsweg (SAT/Enum):** Bit-Allokations-Skript — Varianten-Liste + Mindest-Imm-Breite gegen (mode_bits, imm_bits)-Paare; z3 fuer "passt Mode-Menge in n Bits"-Teilfrage. Warten bis sarithi-Varianten fix.
2. **CMP ist eine Per-Lane-Gleichheits-Maske**, kein klassischer Compare: res=0 (Z) wenn UNGLEICH, 0xFFFFFFFF (S) wenn gleich. Branch-Konvention: `bxx FLAG_S` = "wenn gleich". (pipeline.py:1212)
3. **Imm13 signed (max 4095) erreicht RAM-Basen > 0xFFF nicht** — Pointer-Basis braucht 2 Adds oder ADDSHIFT. Imm-Bereich ist ein echtes Encoding-Limit (Kandidat fuer die SAT-Offset-Frage). **ENTSCHEIDUNG: Long-Jump-Plane verworfen (erstmal), Idiom akzeptiert:** `load pc → arith (off addieren) → bra/brl mit src1=Base` (3 Ops, PC-relative Basis via src1==0-Sonderfall).
4. **Branch-Offsets PC-basiert** (RISC-V-Stil, nicht PC+4): assembler-seitig konsistent halten.
5. **Selbst-Branch (bra .) = Halt-Idiom** (µC-artig) — Simulator erkennt es als Halt.
6. **Layout-Kollisionen lehrreich:** MSR-Region 0x0-0xFFF + RAM-Basis = Daten koennen nicht unter 0x1000 liegen; Code/Daten-Platzierung via load_words-offset (MSR_END).

**bxx-Semantik GELOEST (CMP-Swap-Trick):** `(flags & mask) != 0` reicht — die Negation kommt aus dem CMP, nicht dem Branch (RISC-V-Stil). `bne` = CMP-Operanden swappen (`CMP b,a`) + `bxx Z`. Deckt alle Bedingungen (Z=gleich, S=negativ, C=carry, O=overflow), kein Invert-Bit noetig, ISA-dünn.

**Shell-Stand (Iteration 1.5):** carith (F3), sarith (F2, S-Quellen; F1-ADD), slogi (F2, imm4-LUT-Expand), control (bra/brl/bxx, WRF-Multiplex), memory (ld/st, WRF-Richtung, Breiten-Scale, unaligned via byte-Zugriff), **ternlog (F3, ctrl=volle 256-LUT), permb (F3, Modi 0=byte/1=nibble/2=shift-r/3=shift-l, blank=ctrl-bit7), bitfrob (F3, inv1-3+mode5, write_flags via WRF)**. **sbitfrob (F2, 2-Op-bitfrob, c=0, Gruppe via sub&1) + sshufb (F2, 2-Op-permb: src1=Daten, src2=Lane-Vektor=Control — `permb(a,a,b)`, Gruppe via sub&1)**. cst-Pool bei permb: Iteration 1 offen. Assembler-Helper `ternlog_w/permb_w/bitfrob_w` ergaenzt (sbitfrob/sshufb: Wörter via f2-Layout im Test). Verifikation: Smoke PASS + 75 Differential-Vergleiche (ternlog/permb/bitfrob) + 100 (sbitfrob/sshufb) 0 Mismatches. MSR-Region schreibgeschuetzt.

**Beispiel-Programme (shell_example.py, alle PASS, exit=0):**
- **strlen** "Hello, ISA World!"+NUL: S1-Pointer + S2-Zaehler (S-Gruppe), Byte-Loads, CMP/bxx-Loop, 109 Instr., strlen=17. Funde: (a) **dst global (5 Bit, alle 32) vs src-Felder gruppenrelativ (4 Bit)** — Fehlversuch `dst=1` (=C1) statt `dst=17` (=S1) liess Pointer in C-Gruppe landen und Loop aus MSR-Region lesen; Encoding erzwingt die Regel korrekt. (b) Pointer-Basis 0x1000 via 2 sarithi-Adds (Imm13-Limit live).
- **memcpy** 16 Wörter: ld.w/st.w-Loop mit S-Pointer-Paar, 133 Instr., dst==src verifiziert.
- **strcpy** "copy me!"+NUL: Byte-ld/st, Exit auf Byte==0 (CMP+bxx FLAG_S), 65 Instr.
- **popcount 0x0F0F0F0F → 16**: per-Nibble-POPCNT_N liefert 0x04040404 (KEIN Full-Popcount!); voller Wert via SWAR-Mul-Kette (×0x01010101>>24) oder Microcode (POPCNT_B+horizontale Summe). **Namens-Fund: "POPCNT_N" = Nibble-Lane-Popcount, kein Full-Popcount — Pseudo-Op-Frage (Full-Popcount = Sequenz, nicht 1-Op).**
- **unaligned ld.w @0x1183**: 0xDEADBEEF korrekt (Base 0x1180 + Index 3, byte-genau — Pflicht-Fähigkeit live).

**Harness-Fund + FIX (gefaehrlich):** mem_write verwarf MSR-Region-Stores still (`if addr < MSR_END: return`) — der Builder schoss 0xB80 (< MSR_END) und der Store verschwand kommentarlos. **Gefixt: `warn=True`-Default** (WARN-Print bei verworfenem MSR-Store, `warn=False` fuer stillen Weg). **shell_examples.py ins Repo eingebunden** (die 5 Algos, Regression-Basis: 109/133/65 Instr.).
