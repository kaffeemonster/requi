`ifndef PRIMITIVES_AXI_INTERFACE_SVH
` define PRIMITIVES_AXI_INTERFACE_SVH 1

import axi4_pkg::*;

interface axi4_lite_if #(
    parameter ADDR_WIDTH = 32,
    parameter DATA_WIDTH = 32
) (
    input logic clk, 
    input logic rst_n 
);

    // 1     Write Address Channel (AW)
    logic [ADDR_WIDTH-1:0]     awaddr;
    logic                      awvalid;
    logic                      awready;

    // 2. Write Data Channel (W)
    logic [DATA_WIDTH-1:0]     wdata;
    logic [(DATA_WIDTH/8)-1:0] wstrb; // Welche Bytes sind gültig? (Byte-Enable)
    logic                      wvalid;
    logic                      wready;

    // 3. Write Response Channel (B)
    axi_resp_t                 bresp;
    logic                      bvalid;
    logic                      bready;

    // 4. Read Address Channel (AR)
    logic [ADDR_WIDTH-1:0]     araddr;
    logic                      arvalid;
    logic                      arready;

    // 5. Read Data Channel (R)
    logic [DATA_WIDTH-1:0]     rdata;
    axi_resp_t                 rresp;
    logic                      rvalid;
    logic                      rready;

    // Modport für Ihre CPU (Master)
    modport master (
        input  clk, rst_n,
        output awaddr, awvalid, input awready,
        output wdata, wstrb, wvalid, input wready,
        input  bresp, bvalid, output bready,
        output araddr, arvalid, input arready,
        input  rdata, rresp, rvalid, output rready
    );

    // Modport für die Peripherie / Interconnect (Slave)
    modport slave (
        input  clk, rst_n,
        input  awaddr, awvalid, output awready,
        input  wdata, wstrb, wvalid, output wready,
        output bresp, bvalid, input bready,
        input  araddr, arvalid, output arready,
        output rdata, rresp, rvalid, input rready
    );

endinterface


interface axi4_if #(
    parameter ADDR_WIDTH = 32,
    parameter DATA_WIDTH = 32,
    parameter ID_WIDTH   = 4,
    parameter USER_WIDTH = 1  // Optional: Für benutzerdefinierte Signale
)(
    input logic clk,
    input logic rst_n
);

    // ------------------------------------------------------------------------
    // 1. Write Address Channel (AW)
    // ------------------------------------------------------------------------
    logic [ID_WIDTH-1:0]     awid;     // Transaction ID
    logic [ADDR_WIDTH-1:0]   awaddr;   // Startadresse
    logic [7:0]              awlen;    // Burst-Länge (Anzahl Beats - 1: 0..255)
    axi_size_t               awsize;   // Bytes pro Beat (2^awsize)
    axi_burst_t              awburst;  // Burst-Typ (FIXED, INCR, WRAP)
    axi_lock_t               awlock;   // Atomic Access
    axi_cache_t              awcache;  // Cacheability
    axi_prot_t               awprot;   // Protection Level (Privileged, Secure, Data/Instruction)
    axi_qos_level_t          awqos;    // Quality of Service
    axi_region_t             awregion; // Region Identifier
    logic [USER_WIDTH-1:0]   awuser;   // User Sideband Signals
    logic                    awvalid;  // Master hat gültige Adresse
    logic                    awready;  // Slave ist bereit

    // ------------------------------------------------------------------------
    // 2. Write Data Channel (W)
    // ------------------------------------------------------------------------
    logic [DATA_WIDTH-1:0]   wdata;    // Schreibdaten
    logic [(DATA_WIDTH/8)-1:0] wstrb;  // Byte Enables (dynamisch skaliert!)
    logic                    wlast;    // Kennzeichnet den letzten Beat eines Bursts!
    logic [USER_WIDTH-1:0]   wuser;    // User Sideband
    logic                    wvalid;   // Master hat gültige Daten
    logic                    wready;   // Slave ist bereit

    // ------------------------------------------------------------------------
    // 3. Write Response Channel (B)
    // ------------------------------------------------------------------------
    logic [ID_WIDTH-1:0]     bid;      // Gehört zu dieser Write-Transaction
    axi_resp_t               bresp;    // Status (OKAY, EXOKAY, SLVERR, DECERR)
    logic [USER_WIDTH-1:0]   buser;    // User Sideband
    logic                    bvalid;   // Slave hat Response
    logic                    bready;   // Master akzeptiert Response

    // ------------------------------------------------------------------------
    // 4. Read Address Channel (AR)
    // ------------------------------------------------------------------------
    logic [ID_WIDTH-1:0]     arid;     // Transaction ID
    logic [ADDR_WIDTH-1:0]   araddr;   // Startadresse
    logic [7:0]              arlen;    // Burst-Länge
    axi_size_t               arsize;   // Bytes pro Beat
    axi_burst_t              arburst;  // Burst-Typ
    axi_lock_t               arlock;   // Atomic Access
    axi_cache_t              arcache;  // Cacheability
    axi_prot_t               arprot;   // Protection Level
    axi_qos_level_t          arqos;    // Quality of Service
    axi_region_t             arregion; // Region Identifier
    logic [USER_WIDTH-1:0]   aruser;   // User Sideband
    logic                    arvalid;  // Master hat gültige Adresse
    logic                    arready;  // Slave ist bereit

    // ------------------------------------------------------------------------
    // 5. Read Data Channel (R)
    // ------------------------------------------------------------------------
    logic [ID_WIDTH-1:0]     rid;      // Transaction ID
    logic [DATA_WIDTH-1:0]   rdata;    // Lesedaten
    axi_resp_t               rresp;    // Status
    logic                    rlast;    // Kennzeichnet den letzten Beat eines Bursts!
    logic [USER_WIDTH-1:0]   ruser;    // User Sideband
    logic                    rvalid;   // Slave hat Daten
    logic                    rready;   // Master akzeptiert Daten

    // ------------------------------------------------------------------------
    // Modports
    // ------------------------------------------------------------------------
    modport master (
        input  clk, rst_n,
        output awid, awaddr, awlen, awsize, awburst, awlock, awcache, awprot, awqos, awregion, awuser, awvalid,
        input  awready,
        output wdata, wstrb, wlast, wuser, wvalid,
        input  wready,
        input  bid, bresp, buser, bvalid,
        output bready,
        output arid, araddr, arlen, arsize, arburst, arlock, arcache, arprot, arqos, arregion, aruser, arvalid,
        input  arready,
        input  rid, rdata, rresp, rlast, ruser, rvalid,
        output rready
    );

    modport slave (
        input  clk, rst_n,
        input  awid, awaddr, awlen, awsize, awburst, awlock, awcache, awprot, awqos, awregion, awuser, awvalid,
        output awready,
        input  wdata, wstrb, wlast, wuser, wvalid,
        output wready,
        output bid, bresp, buser, bvalid,
        input  bready,
        input  arid, araddr, arlen, arsize, arburst, arlock, arcache, arprot, arqos, arregion, aruser, arvalid,
        output arready,
        output rid, rdata, rresp, rlast, ruser, rvalid,
        input  rready
    );

endinterface


`endif
