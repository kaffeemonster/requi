`include "axi_interface.svh"

module axi4_to_axilite_bridge #(
    parameter ADDR_WIDTH = 32,
    parameter DATA_WIDTH = 32,
    parameter ID_WIDTH   = 4
)(
    input logic clk,
    input logic rst_n,

    // AXI4 Full Master Interface
    axi4_if.slave  m_axi4,   // Bridge verhält sich wie ein Slave gegenüber dem AXI4-Master

    // AXI4-Lite Slave Interface
    axi4_lite_if.master s_axil // Bridge verhält sich wie ein Master gegenüber dem Lite-Slave
);

    // ------------------------------------------------------------------------
    // READ CHANNEL STATE MACHINE (Burst Breaking)
    // ------------------------------------------------------------------------
    typedef enum logic [1:0] {
        R_IDLE,
        R_TRANSFER,
        R_WAIT_READY
    } r_state_t;
    typedef axi4_pkg::axi_helpers#(ADDR_WIDTH, DATA_WIDTH) axi_utils;

    r_state_t r_state;

    logic [ID_WIDTH-1:0]   r_id_reg;
    logic [ADDR_WIDTH-1:0] r_addr_reg;
    logic  [ADDR_WIDTH-1:0] next_addr;
    logic [7:0]            r_len_cnt;
    logic [7:0]            r_len_bak;
    axi_size_t             r_size_reg;
    axi_burst_t            r_burstt_reg;
    
    always_comb begin
        next_addr = axi_utils::get_next_addr_nowrap(r_addr_reg, r_burstt_reg, r_size_reg, r_len_bak);
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            r_state        <= R_IDLE;
            m_axi4.arready <= 1'b1;
            s_axil.arvalid <= 1'b0;
            m_axi4.rvalid  <= 1'b0;
            m_axi4.rlast   <= 1'b0;
            s_axil.rready  <= 1'b0;
            r_len_cnt      <= 8'd0;
            r_burstt_reg   <= AXI_BURST_INCR;
            r_len_bak      <= 8'd0;
        end else begin
            case (r_state)
                R_IDLE: begin
                    m_axi4.rlast <= 1'b0;
                    if (m_axi4.arvalid && m_axi4.arready) begin
                        // Transaktion sichern
                        r_id_reg     <= m_axi4.arid;
                        r_addr_reg   <= m_axi4.araddr;
                        r_len_cnt    <= m_axi4.arlen;
                        r_len_bak    <= m_axi4.arlen;
                        r_size_reg   <= m_axi4.arsize;

                        m_axi4.arready <= 1'b0; // Blockiere neue AXI4 AR-Requests während Burst

                        // Ersten Lite-Read anstoßen
                        s_axil.araddr  <= m_axi4.araddr;
                        s_axil.arvalid <= 1'b1;
                        s_axil.rready  <= 1'b1;
                        r_state        <= R_TRANSFER;
                    end
                end

                R_TRANSFER: begin
                    // Warten bis Lite-Slave die Adresse akzeptiert hat
                    if (s_axil.arvalid && s_axil.arready) begin
                        s_axil.arvalid <= 1'b0;
                    end

                    // Sobald Daten vom Lite-Slave kommen -> an AXI4 Master weiterleiten
                    if (s_axil.rvalid && s_axil.rready) begin
                        m_axi4.rdata  <= s_axil.rdata;
                        m_axi4.rresp  <= s_axil.rresp;
                        m_axi4.rid    <= r_id_reg;
                        m_axi4.rvalid <= 1'b1;

                        // Ist das der letzte Beat des Bursts?
                        if (r_len_cnt == 8'd0) begin
                            m_axi4.rlast <= 1'b1;
                            r_state      <= R_WAIT_READY;
                        end else begin
                            r_len_cnt  <= r_len_cnt - 1'b1;
                            // Adresse für nächsten Beat berechnen (INCR Burst: + (1 << size))
                            r_addr_reg <= next_addr;
                            
                            // Nächsten Beat auf AXI-Lite anfordern
                            s_axil.araddr  <= next_addr;
                            s_axil.arvalid <= 1'b1;
                        end
                    end
                end

                R_WAIT_READY: begin
                    // Warten, bis der AXI4 Master den letzten Beat quittiert hat
                    if (m_axi4.rvalid && m_axi4.rready) begin
                        m_axi4.rvalid  <= 1'b0;
                        m_axi4.rlast   <= 1'b0;
                        m_axi4.arready <= 1'b1; // Bereit für nächsten AXI4 Burst
                        r_state        <= R_IDLE;
                    end
                end
            endcase
        end
    end

    // ------------------------------------------------------------------------
    // WRITE CHANNEL (Verkürzte Handshake-Logik für 1-Beat Writes)
    // ------------------------------------------------------------------------
    // Für die Schreibseite gilt dasselbe Prinzip: Adresse & Daten an AXI-Lite
    // durchreichen, Beats abzählen, und bei wlast das B-Response-Signal erzeugen.

    logic [ID_WIDTH-1:0] w_id_reg;
//TODO: also needs write burst state machine
    // Einfache Adress- und Datenkopplung (Einschränkung: setzt voraus, dass AW und W synchron ankommen)
    assign s_axil.awaddr  = m_axi4.awaddr;
    assign s_axil.awvalid = m_axi4.awvalid;
    assign m_axi4.awready = s_axil.awready;

    assign s_axil.wdata   = m_axi4.wdata;
    assign s_axil.wstrb   = m_axi4.wstrb;
    assign s_axil.wvalid  = m_axi4.wvalid;
    assign m_axi4.wready  = s_axil.wready;

    // Write Response Weiterleitung
    assign m_axi4.bid     = w_id_reg;
    assign m_axi4.bresp   = s_axil.bresp;
    assign m_axi4.bvalid  = s_axil.bvalid;
    assign s_axil.bready  = m_axi4.bready;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            w_id_reg <= '0;
        end else if (m_axi4.awvalid && m_axi4.awready) begin
            w_id_reg <= m_axi4.awid; // ID für B-Channel merken
        end
    end

endmodule : axi4_to_axilite_bridge
