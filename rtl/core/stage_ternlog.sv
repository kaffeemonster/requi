(* syn_hier = "hard" *) // Protects this specific pipeline hierarchy in Gowin

// 1. Definition der Typen (z. B. in einem Package oder Modul)
typedef struct packed {
    logic zero;      // Bit 3
    logic overflow;  // Bit 2
    logic negative;  // Bit 1
    logic carry;     // Bit 0
} alu_flags_t;


module stage_ternlog #(
    parameter RLEN = 64
) (
    input  logic [RLEN-1:0] work_in,
    input  logic [RLEN-1:0] src1_in,
    input  logic [RLEN-1:0] src2_in,
    input  logic [RLEN-1:0] src3_in,
    input  logic [RLEN-1:0] constp,
    input  logic [7:0]      logic_op,
    input  alu_flags_t      flags_in,
    input  logic [4:0]      aux_ctrl,
    input  logic            clk,
    input  logic            flags_en,
    output logic [RLEN-1:0] work_out,
    output logic [RLEN-1:0] src1_out,
    output logic [RLEN-1:0] src2_out,
    output logic [RLEN-1:0] src3_out,
    output alu_flags_t      flags_out
);

    logic [RLEN-1:0] to_out, src1_reg, src2_reg, src3_reg;
// Gowin attribute ensures these registers are not optimized out/merged
    (* syn_preserve = 1 *) logic [RLEN-1:0] work_out_reg;
    (* syn_preserve = 1 *) alu_flags_t      flags_out_reg;


    log_ternlog #(
        .WIDTH (RLEN)
    ) log_tern_inst (
        .a   (src1_in),
        .b   (src2_in),
        .c   (src3_in),
        .imm (logic_op),
        .out (to_out)
    );

    // Sequential pipeline stage
    always_ff @(posedge clk) begin
        src1_reg <= src1_in;
        src2_reg <= src2_in;
        src3_reg <= src3_in;
        // Mix in wrkin, cnstp, and aux_ctrl via a basic conditional mux 
        // to prevent the compiler from stripping these inputs out.
        if (aux_ctrl == '0) begin
            work_out_reg <= to_out ^ work_in;
        end else begin
            work_out_reg <= to_out ^ constp;
        end

        // flags logic
        if (flags_en) begin
            flags_out_reg = '0;
            flags_out_reg.zero = (to_out == '0);
            flags_out_reg.negative = to_out[RLEN-1];
        end else begin
            flags_out_reg <= flags_in;
        end
    end

    // Drive outputs from the preserved registers
    assign wrk_out   = work_out_reg;
    assign src1_out  = src1_reg;
    assign src2_out  = src2_reg;
    assign src3_out  = src3_reg;
    assign flags_out = flags_out_reg;
endmodule : stage_ternlog

module log_ternlog #(
    parameter WIDTH = 64
) (
    input  logic [WIDTH-1:0] a,
    input  logic [WIDTH-1:0] b,
    input  logic [WIDTH-1:0] c,
    input  logic [7:0] imm,
    output logic [WIDTH-1:0] out
);

    // This attribute tells Gowin to preserve this exact logic boundary
    //   (* syn_keep = 1 *) logic [31:0] ternlog_lut_out;

    always_comb begin
        foreach (out[i]) begin
            out[i] = imm[{a[i], b[i], c[i]}];
        end
    end
endmodule : log_ternlog