`ifndef PRIMITIVES_SDRAM_PHY_SVH
` define PRIMITIVES_SDRAM_PHY_SVH 1

// ============================================================================
// Interface: sdram_phy_if
// Kapselt alle physikalischen SDRAM-Pins gemäß der .cst-Datei
// ============================================================================
interface sdram_phy_single_if ();

    // -- Signale (exakte Namen wie in der .cst-Datei) --
    logic        clk;      // Taktausgang
    logic        cke;      // Clock Enable
    logic        cs_n;     // Chip Select (neg.)
    logic        ras_n;    // Row Address Strobe (neg.)
    logic        cas_n;    // Column Address Strobe (neg.)
    logic        wen_n;     // Write Enable (neg.)
    logic [1:0]  ba;       // Bank Address
    logic [1:0]  dqm;      // Data Mask (je Byte)
    logic [12:0] addr;     // Adresse (13 Bit)
    wire  [15:0] dq;       // Datenbus (bidirektional → zwingend 'wire')

    // -- Modport für den Speicher-Controller (RTL-Logik) --
    modport controller (
        output clk,        // Alle Steuersignale werden vom Controller getrieben
        output cke,
        output cs_n,
        output ras_n,
        output cas_n,
        output wen_n,
        output ba,
        output dqm,
        output addr,
        inout  dq          // Bidirektional – Controller muss Tri-State steuern
    );

    // -- Modport für die physikalische FPGA-Pin-Anbindung (Top-Level) --
    modport physical (
        output clk,
        output cke,
        output cs_n,
        output ras_n,
        output cas_n,
        output wen_n,
        output ba,
        output dqm,
        output addr,
        inout  dq          // Geht direkt an die FPGA-I/O-Pads
    );

    // -- Optionaler Clocking-Block für Testbenches / glitchfreies TB-Sampling --
    // (Nur für Simulation, nicht für Synthese relevant)
    clocking monitor_cb @(posedge clk);
        default input #1step output #1step;
        input  cke, cs_n, ras_n, cas_n, wen_n;
        input  ba, dqm, addr;
        inout  dq;
    endclocking

    // ---- Modport: High-Level Speicher-Schnittstelle (abstrahiert) ----
    // Hier werden nur die logischen Signale durchgereicht, die der
    // eigentliche Speicher-Controller (z.B. AXI-Bridge) sehen soll.
    modport memory_if (
        // Takt & Reset kommen von außen (nicht im Interface)
        // Nur die "echten" Memory-Signale:
        output cke,      // Clock Enable (logisch)
        output cs_n,
        output ras_n,
        output cas_n,
        output wen_n,
        output ba,
        output dqm,
        output addr,
        inout  dq
    );

endinterface

`endif