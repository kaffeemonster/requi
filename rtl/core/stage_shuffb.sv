(* syn_hier = "hard" *)
module stage_shuffb #(
    parameter int RLEN = 64
) (
    input  logic [RLEN-1:0] src1,       
    input  logic [RLEN-1:0] src2,       
    input  logic [RLEN-1:0] src3,       
    input  logic [3:0]      cpool_idx,  
    input  logic            use_cpool,  
    input  logic [7:0]      mode_reg,   
    output logic [RLEN-1:0] shuffle_out
);

    localparam int BYTES = RLEN / 8;
    localparam int NIBBLES = RLEN / 4;

    // 1. Resolve Operand C
    logic [RLEN-1:0] operand_c;
    logic [RLEN-1:0] cpool_vector;

    always_comb begin
        case (cpool_idx)
            4'h0: cpool_vector = 64'h0001020304050607;
            4'h1: cpool_vector = 64'h0706050403020100;
            4'h2: cpool_vector = 64'h0f0f0f0f0f0f0f0f;
            4'h3: cpool_vector = 64'h5555aaaa5555aaaa;
            4'h4: cpool_vector = 64'h1b1b1b1b1b1b1b1b;
            default: cpool_vector = '0;
        endcase
    end

    assign operand_c = use_cpool ? cpool_vector : src3;

    // 2. Decode Register Flags
    logic mode_nibble; 
    logic mode_zero_en;
    assign mode_nibble  = mode_reg[0]; 
    assign mode_zero_en = mode_reg[1]; 

    // 3. Execution Core using clean wire-arrays (avoids always_comb select indexing bugs)
    logic [RLEN-1:0] byte_shuffled;
    logic [RLEN-1:0] nibble_shuffled;

    // Generiert exakt parallele Hardware-Multiplexer, die Icarus fehlerfrei parsen kann
    genvar i;
    generate
        // Byte Muxes
        for (i = 0; i < BYTES; i = i + 1) begin : gen_byte_mux
            wire [7:0] ctrl_byte = src2[i*8 +: 8];
            wire [2:0] sel_idx   = ctrl_byte[2:0];
            wire       pool_sel  = ctrl_byte[3]; // Bit 3 entscheidet: src1 oder operand_c

            assign byte_shuffled[i*8 +: 8] = (mode_zero_en && ctrl_byte[7]) ? 8'h00 : 
                                             (pool_sel ? operand_c[sel_idx*8 +: 8] : src1[sel_idx*8 +: 8]);
        end

        // Nibble Muxes
        for (i = 0; i < NIBBLES; i = i + 1) begin : gen_nibble_mux
            wire [3:0] ctrl_nibble = src2[i*4 +: 4];
            wire [2:0] sel_idx     = ctrl_nibble[2:0];
            wire       pool_sel    = ctrl_nibble[3];

            assign nibble_shuffled[i*4 +: 4] = pool_sel ? operand_c[sel_idx*4 +: 4] : src1[sel_idx*4 +: 4];
        end
    endgenerate

    // 4. Output Mux
    assign shuffle_out = mode_nibble ? nibble_shuffled : byte_shuffled;

endmodule
