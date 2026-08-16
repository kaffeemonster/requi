`timescale 1ns/1ps

(* syn_hier = "hard" *) // Ensure Gowin maintains this critical pipeline boundary
module execution_pipeline_top #(
    parameter int RLEN = 64
) (
    input  logic              clk,
    input  logic              rst_n,        // Active-low asynchronous reset

    // Global Pipeline Control
    input  logic              ex1_valid,    // Valid flag for Stage 1 inputs
    input  logic              ex2_valid,    // Valid flag for Stage 2 inputs

    // Stage 1 (Shuffle) Inputs
    input  logic [RLEN-1:0]   ex1_src1,     
    input  logic [RLEN-1:0]   ex1_src2,     // Index control matrix
    input  logic [RLEN-1:0]   ex1_src3,     
    input  logic [3:0]        ex1_cpool_idx,
    input  logic              ex1_use_cpool,
    input  logic [7:0]        ex1_shuf_mode,

    // Stage 2 (Ternlog + Flags) Inputs / Controls
    input  logic [RLEN-1:0]   ex2_wrkin,    // Forwarded network or bypass input
    input  logic [RLEN-1:0]   ex2_cnstp,    
    input  logic [7:0]        ex2_logic_op, // imm8 value for ternary logic
    input  logic [7:0]        ex2_flags_in, 
    input  logic              ex2_flags_en, 
    input  logic              ex2_aux_ctrl, 

    // Monitored Pipeline Outputs (from Stage 2 Register)
    output logic [RLEN-1:0]   pipe_wrkout,
    output logic [7:0]        pipe_flags_out
);

    // ------------------------------------------------------------------------
    // INTER-STAGE INTERCONNECTS
    // ------------------------------------------------------------------------
    logic [RLEN-1:0] ex1_shuf_out;          // Combinational out from Stage 1
    
    // Protected Pipeline Pipeline Registers (Stage 1 -> Stage 2)
    (* syn_preserve = 1 *) logic [RLEN-1:0] ex2_reg_shuf_data;
    (* syn_preserve = 1 *) logic [RLEN-1:0] ex2_reg_src2_fwd;
    (* syn_preserve = 1 *) logic [RLEN-1:0] ex2_reg_src3_fwd;

    // ------------------------------------------------------------------------
    // STAGE 1: SHUFFLE & PERMUTATION ENGINE (Combinational)
    // ------------------------------------------------------------------------
    stage_shuffb #(.RLEN(RLEN)) shuf_inst (
        .src1       (ex1_src1),
        .src2       (ex1_src2),
        .src3       (ex1_src3),
        .cpool_idx  (ex1_cpool_idx),
        .use_cpool  (ex1_use_cpool),
        .mode_reg   (ex1_shuf_mode),
        .shuffle_out(ex1_shuf_out)
    );

    // ------------------------------------------------------------------------
    // PIPELINE REGISTER BUFFERING
    // ------------------------------------------------------------------------
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            ex2_reg_shuf_data <= '0;
            ex2_reg_src2_fwd  <= '0;
            ex2_reg_src3_fwd  <= '0;
        end else if (ex1_valid) begin
            // Capture permuted vector from Stage 1
            ex2_reg_shuf_data <= ex1_shuf_out;
            
            // Forward raw operand inputs downstream in case the decoder calls 
            // for direct un-shuffled mixing inside the Ternlog stage
            ex2_reg_src2_fwd  <= ex1_src2;
            ex2_reg_src3_fwd  <= ex1_src3;
        end
    end

    // ------------------------------------------------------------------------
    // STAGE 2: BITWISE TERNARY LOGIC & DUMMY INTERLOCKS (Registered)
    // ------------------------------------------------------------------------
    // We map the dynamically shuffled vector straight into the 'A' input of ternlog
    stage_ternlog #(.RLEN(RLEN)) ternlog_inst (
        .clk      (clk),
        .src1     (ex2_reg_shuf_data), // Input A = Shuffled output vector
        .src2     (ex2_reg_src2_fwd),  // Input B = Forwarded matrix register
        .src3     (ex2_reg_src3_fwd),  // Input C = Forwarded baseline register
        .wrkin    (ex2_wrkin),
        .cnstp    (ex2_cnstp),
        .logic_op (ex2_logic_op),
        .flags_in (ex2_flags_in),
        .flags_en (ex2_flags_en && ex2_valid),
        .aux_ctrl (ex2_aux_ctrl),
        .wrkout   (pipe_wrkout),
        .flags_out(pipe_flags_out)
    );

endmodule
