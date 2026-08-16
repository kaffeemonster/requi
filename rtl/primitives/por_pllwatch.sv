// ========================================================================
// POR mit PLL-Watchdog - Mehrere Lock-Versuche
// ========================================================================
module por_pllwatch #(
    parameter real POR_DELAY_MS = 10.0,           // Zeit pro Versuch (kürzer!)
    parameter real CLK_FREQ_MHZ = 50.0,
    parameter int MAX_RETRIES = 5                 // Maximale Anzahl Versuche
)(
    input  wire clk,
    input  wire pll_locked,
    input  wire ext_rst_n,
    output wire rst_n,
    output wire pll_error                         // Optional: Fehler anzeigen
);

    localparam int COUNTER_MAX = int'(POR_DELAY_MS * CLK_FREQ_MHZ * 1000.0);
    localparam int COUNTER_WIDTH = $clog2(COUNTER_MAX);
    localparam int RETRY_WIDTH = $clog2(MAX_RETRIES + 1);

    // --------------------------------------------------------------------
    // Signale
    // --------------------------------------------------------------------
    logic [COUNTER_WIDTH-1:0] counter;
    logic [RETRY_WIDTH-1:0]   retry_count;
    logic por_active;
    logic counter_zero;
    logic lock_failed;

    assign counter_zero = (counter == 0);

    // --------------------------------------------------------------------
    // Zustandsautomat
    // --------------------------------------------------------------------
    enum logic [2:0] {
        IDLE        = 3'b000,
        COUNT       = 3'b001,
        CHECK_LOCK  = 3'b010,
        RELEASE     = 3'b011,
        ERROR       = 3'b100,
        RETRY_DELAY = 3'b101   // Kleine Pause zwischen Versuchen
    } state, next_state;

    // --------------------------------------------------------------------
    // Sequenzielle Logik
    // --------------------------------------------------------------------
    always_ff @(posedge clk or negedge ext_rst_n) begin
        if (!ext_rst_n) begin
            state       <= IDLE;
            counter     <= COUNTER_MAX - 1;
            retry_count <= '0;
            por_active  <= 1'b1;
            lock_failed <= 1'b0;
        end else begin
            state <= next_state;

            case (state)
                // ------------------------------------------------------------
                IDLE: begin
                    counter     <= COUNTER_MAX - 1;
                    retry_count <= '0;
                    por_active  <= 1'b1;
                    lock_failed <= 1'b0;
                end

                // ------------------------------------------------------------
                COUNT: begin
                    if (counter != 0)
                        counter <= counter - 1;
                    // Bei counter_zero: bleibt stehen
                    por_active <= 1'b1;
                end

                // ------------------------------------------------------------
                CHECK_LOCK: begin
                    counter <= COUNTER_MAX - 1;  // Für nächsten Versuch
                    por_active <= 1'b1;
                    
                    if (pll_locked) begin
                        // PLL ist gelockt!
//                        next_state = RELEASE;    // Wird im Kombinatorik-Teil überschrieben
                    end else begin
                        // PLL noch nicht gelockt
                        if (retry_count < MAX_RETRIES - 1) begin
                            retry_count <= retry_count + 1;
                            // Gehe zu RETRY_DELAY (wird im Kombinatorik-Teil gesetzt)
                        end else begin
                            // Zu viele Versuche -> Fehler
                            lock_failed <= 1'b1;
                            // Gehe zu ERROR (wird im Kombinatorik-Teil gesetzt)
                        end
                    end
                end

                // ------------------------------------------------------------
                RETRY_DELAY: begin
                    // Kleine Pause (z.B. 1ms) zwischen Versuchen
                    if (counter != 0)
                        counter <= counter - 1;
                    por_active <= 1'b1;
                end

                // ------------------------------------------------------------
                RELEASE: begin
                    counter     <= COUNTER_MAX - 1;
                    retry_count <= '0;
                    por_active  <= 1'b0;
                    lock_failed <= 1'b0;
                end

                // ------------------------------------------------------------
                ERROR: begin
                    counter     <= COUNTER_MAX - 1;
                    por_active  <= 1'b1;     // System bleibt im Reset!
                    lock_failed <= 1'b1;     // Fehler signalisieren
                end
            endcase
        end
    end

    // --------------------------------------------------------------------
    // Kombinatorische Logik (Zustandsübergänge)
    // --------------------------------------------------------------------
    always_comb begin
        next_state = state;

        unique case (state)
            IDLE: begin
                // Sofort mit dem ersten COUNT starten
                next_state = COUNT;
            end

            COUNT: begin
                if (counter == 0)
                    next_state = CHECK_LOCK;
            end

            CHECK_LOCK: begin
                if (pll_locked) begin
                    next_state = RELEASE;
                end else begin
                    if (retry_count < MAX_RETRIES - 1)
                        next_state = RETRY_DELAY;
                    else
                        next_state = ERROR;
                end
            end

            RETRY_DELAY: begin
                if (counter == 0)
                    next_state = COUNT;  // Nächsten Versuch starten
            end

            RELEASE: begin
                if (!ext_rst_n)
                    next_state = IDLE;
            end

            ERROR: begin
                // Im Fehlerfall: Nur externer Reset hilft
                if (!ext_rst_n)
                    next_state = IDLE;
            end
        endcase
    end

    // --------------------------------------------------------------------
    // Ausgänge
    // --------------------------------------------------------------------
    assign rst_n     = !por_active;
    assign pll_error = lock_failed;

endmodule
