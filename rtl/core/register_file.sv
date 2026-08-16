(* syn_hier = "hard" *)
module cpu_hybrid_regfile #(
    parameter int RLEN          = 64,
    parameter bit DOUBLE_PUMPED = 1,   // 0 = Fast Distributed, 1 = Double-Pumped (Clock x2)
    parameter int REG_ID_WIDTH = 5      // 32 Allzweck-Register

) (
    input  logic        clk,            // Haupt-CPU-Takt
    input  logic        clk_x2,         // Doppelter Takt (nur benötigt wenn DOUBLE_PUMPED=1)
    input  logic        rst_n,

    // Lese-Ports (5-Bit Adressen für 32 Register insgesamt)
    // Reg 0..15  -> Complex Registers (3 Read Ports verfügbar)
    // Reg 16..31 -> Simple Registers  (Nur Read Port 1 & 2 verfügbar)
    input  logic [4:0]      raddr1,
    output logic [RLEN-1:0] rdata1,

    input  logic [4:0]      raddr2,
    output logic [RLEN-1:0] rdata2,

    input  logic [4:0]      raddr3,         // Nur gültig für Adressen 0..15!
    output logic [RLEN-1:0] rdata3,

    // Schreib-Port (Wahlfrei auf alle 32 Register)
    input  logic            we,
    input  logic [4:0]      waddr,
    input  logic [RLEN-1:0] wdata
);

    // Adress-Validierung für Read Port 3 (Sicherheits-Nullung)
/*
    logic raddr1_is_complex, raddr2_is_complex, raddr3_is_complex, waddr_is_complex;
    always_ff @(posedge clk) begin
        raddr1_is_complex = (raddr1 < 5'd16);
        raddr2_is_complex = (raddr2 < 5'd16);
        raddr3_is_complex = (raddr3 < 5'd16);
        waddr_is_complex = (waddr < 5'd16);
    end
*/

    // ========================================================================
    // VARIANTE 1: SCHNELLE VERSION (Manuelle Duplikation für SSRAM-Inferenz)
    // ========================================================================
    if (DOUBLE_PUMPED == 0 || DOUBLE_PUMPED == 1) begin : gen_fast_parallel
        // Jedes dieser Arrays hat jetzt nur noch genau EIN Lese-Auge!
        logic [RLEN-1:0] complex_bank_A [16];
        logic [RLEN-1:0] complex_bank_B [16];
        logic [RLEN-1:0] complex_bank_C [16];

        logic [RLEN-1:0] simple_bank_A  [16];
        logic [RLEN-1:0] simple_bank_B  [16];

        logic [RLEN-1:0] null_reg;
        logic [RLEN-1:0] rdata1_reg;
        logic [RLEN-1:0] rdata2_reg;
        logic [RLEN-1:0] rdata3_reg;

        always_ff @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                rdata1_reg <= '0;
                rdata2_reg <= '0;
                rdata3_reg <= '0;
                // SSRAM initialisiert sich automatisch im Fabric
            end else if (we) begin
                if (waddr[3:0] != 5'd0) begin
                    null_reg <= wdata;
                end if (!waddr[4]) begin
                    complex_bank_A[waddr[3:0]] <= wdata;
                    complex_bank_B[waddr[3:0]] <= wdata;
                    complex_bank_C[waddr[3:0]] <= wdata;
                end else begin
                    simple_bank_A[waddr[3:0]]  <= wdata;
                    simple_bank_B[waddr[3:0]]  <= wdata;
                end
            end else begin
                // C0 and S0 are zero regs
                if (!raddr1[4]) begin
                    rdata1_reg <= complex_bank_A[raddr1[3:0]];
                end else begin
                    rdata1_reg <= simple_bank_A[raddr1[3:0]];
                end
                // C0 and S0 are zero regs
                if (!raddr2[4]) begin
                    rdata2_reg <= complex_bank_B[raddr2[3:0]];
                end else begin
                    rdata2_reg <= simple_bank_B[raddr2[3:0]];
                end
                // C0 and S0 are zero regs
                if (!raddr3[4]) begin
                    rdata3_reg <= complex_bank_C[raddr3[3:0]];
                end else begin
// TODO: maybe read constant pool
                    rdata3_reg <= '0;
                end
            end
        end

        assign rdata1 = rdata1_reg;
        assign rdata2 = rdata2_reg;
        assign rdata3 = rdata3_reg;
    end

endmodule
