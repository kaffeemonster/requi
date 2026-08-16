// ====================================================================
// AXI4-Full Slave to Gowin SDRAM HS-Controller Bridge
// ====================================================================
`timescale 1ns / 1ps
` include "axi_interface.svh"
` include "gowin_tang_sdcon_if.svh"
 module axi_gowin_sdram #(
    parameter ADDR_WIDTH = 32,
    parameter DATA_WIDTH = 32
) (
    input  logic        clk_sys,          // Systemtakt (z.B. 100 MHz aus PLL)
    input  logic        rst_n,            // Synchroner Reset (Low-aktiv)

    // --- AXI4 Slave Interface (32-bit Data) ---
    axi4_if.slave  m_axi4,

    // --- INTERFACE ZUM GOWIN HS-CONTROLLER ---
    gowin_tang_sdcon_if.user rc_if
);
// FSM Typedef
typedef enum logic [1:0] {
    ST_IDLE,
    ST_PHASE_LOW,
    ST_PHASE_HIGH
} state_t;

state_t state;

// Internal Registers
logic        is_write;
logic [23:1] word_addr_reg; // Track current 32-bit AXI word boundary
logic [7:0]  len_cnt;       // Keep track of remaining AXI beats
logic [7:0]  r_len_cnt;     // Read pipeline tracking counter
logic [15:0] rdata_hold;    // Hold buffer for lower 16-bit payload

// Fixed AXI responses (OKAY)
assign m_axi4.bresp = AXI_RESP_OKAY;
assign m_axi4.rresp = AXI_RESP_OKAY;

// --- Command Engine FSM ---
always_ff @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        state             <= ST_IDLE;
        m_axi4.awready    <= 1'b0;
        m_axi4.wready <= 1'b0;
        m_axi4.bvalid     <= 1'b0;
        m_axi4.arready    <= 1'b0;
        rc_if.cmd_en      <= 1'b0;
        word_addr_reg     <= '0;
        len_cnt           <= '0;
        is_write          <= 1'b0;
    end else if (rc_if.init_done) begin
        
        case (state)
            ST_IDLE: begin
                if (m_axi4.bvalid && m_axi4.bready) m_axi4.bvalid <= 1'b0;

                // 1. Process Write Requests
                if (m_axi4.awvalid && m_axi4.wvalid && !m_axi4.bvalid) begin
                    word_addr_reg  <= m_axi4.awaddr[23:1];
                    len_cnt        <= m_axi4.awlen;
                    is_write       <= 1'b1;
                    m_axi4.awready <= 1'b1;
                    m_axi4.wready  <= 1'b1;
                    state          <= ST_PHASE_LOW;
                end
                // 2. Process Read Requests
                else if (m_axi4.arvalid) begin
                    word_addr_reg  <= m_axi4.araddr[23:1];
                    len_cnt        <= m_axi4.arlen;
                    is_write       <= 1'b0;
                    m_axi4.arready <= 1'b1;
                    state          <= ST_PHASE_LOW;
                end
            end

            ST_PHASE_LOW: begin
                m_axi4.awready <= 1'b0;
                m_axi4.arready <= 1'b0;

                // Issue command for lower 16-bit word
                rc_if.cmd_en   <= 1'b1;
                rc_if.cmd      <= is_write ? 3'b010 : 3'b001;
                rc_if.addr     <= {word_addr_reg[23:2], 1'b0}; 
                rc_if.data_in  <= m_axi4.wdata[15:0];
                rc_if.dqm      <= is_write ? ~m_axi4.wstrb[1:0] : 2'b00;

                if (rc_if.cmd_ack) begin
                    rc_if.cmd_en <= 1'b0;
                    state        <= ST_PHASE_HIGH;
                end
            end

            ST_PHASE_HIGH: begin
                m_axi4.wready <= 1'b0; // AXI WREADY dropped right before stepping

                // Issue command for upper 16-bit word
                rc_if.cmd_en   <= 1'b1;
                rc_if.cmd      <= is_write ? 3'b010 : 3'b001;
                rc_if.addr     <= {word_addr_reg[23:2], 1'b1};
                rc_if.data_in  <= m_axi4.wdata[31:16];
                rc_if.dqm      <= is_write ? ~m_axi4.wstrb[3:2] : 2'b00;

                if (rc_if.cmd_ack) begin
                    rc_if.cmd_en <= 1'b0;
                    
                    if (len_cnt == 0) begin
                        // Burst completed
                        state <= ST_IDLE;
                        if (is_write) m_axi4.bvalid <= 1'b1;
                    end else begin
                        // Step to the next sequential AXI word address position
                        len_cnt       <= len_cnt - 1'b1;
                        word_addr_reg <= word_addr_reg + 1'b1;
                        if (is_write) m_axi4.wready <= 1'b1; // Pulse ready for next beat
                        state         <= ST_PHASE_LOW;
                    end
                end
            end
        endcase
    end
end

// --- Read Pipeline Counter Tracking ---
// Tracks length attributes separately because data valid lines are delayed
always_ff @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        r_len_cnt <= '0;
    end else if (m_axi4.arvalid && m_axi4.arready) begin
        r_len_cnt <= m_axi4.arlen;
    end else if (m_axi4.rvalid && m_axi4.rready && !m_axi4.rlast) begin
        r_len_cnt <= r_len_cnt - 1'b1;
    end
end

// --- Read Data Re-assembly Pipeline ---
// Watches data arriving from the SDRAM controller layout
always_ff @(posedge clk_sys or negedge rst_n) begin
    if (!rst_n) begin
        m_axi4.rdata  <= '0;
        m_axi4.rvalid <= 1'b0;
        m_axi4.rlast  <= 1'b0;
        rdata_hold   <= '0;
    end else begin
        if (m_axi4.rvalid && m_axi4.rready) begin
            m_axi4.rvalid <= 1'b0;
            m_axi4.rlast  <= 1'b0;
        end

        if (rc_if.cmd_ack) begin
            // Identify low-byte or high-byte by checking incoming address phase bit
            if (rc_if.addr[0] == 1'b0) begin
                rdata_hold <= rc_if.data_in;
            end else begin
                m_axi4.rdata  <= {rc_if.data_in, rdata_hold};
                m_axi4.rvalid <= 1'b1;
                m_axi4.rlast  <= (r_len_cnt == 0);
            end
        end
    end
end
endmodule