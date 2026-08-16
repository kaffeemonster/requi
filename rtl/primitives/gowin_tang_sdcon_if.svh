`ifndef PRIMITIVES_GOWIN_TANG_SDCON_IF_SVH
` define PRIMITIVES_GOWIN_TANG_SDCON_IF_SVH 1


// ============================================================================
// Interface: gowin_tang_sdcon_if
// Kapselt alle Kontroll-Signale des Gowin SDRAM Controllers
// passend für Siped Tanf Mem mod
// ============================================================================
interface gowin_tang_sdcon_if ();

    logic        cmd_en;
    logic [2:0]  cmd;       // 3'b011 = WR, 3'b100 = RD
    logic [23:0] addr;
    logic [15:0] data_out;
    logic [8:0]  data_len;
    logic [15:0] data_in;
    logic [1:0]  dqm;
    logic        init_done;
    logic        cmd_ack;
    logic        precharge_ctrl;
    logic        power_down;
    logic        selfrefresh;
    
    modport controller (
        input  cmd_en,
        input  cmd,
        input  addr,
        input  data_in,
        input  data_len,
        input  dqm,
        output data_out,
        output init_done,
        output cmd_ack,
        output precharge_ctrl,
        output power_down,
        output selfrefresh
    );
    
    modport user (
        output cmd_en,
        output cmd,
        output addr,
        output data_in,
        output data_len,
        output dqm,
        input  data_out,
        input  init_done,
        input  cmd_ack,
        input  precharge_ctrl,
        input  power_down,
        input  selfrefresh
    );

endinterface

`endif