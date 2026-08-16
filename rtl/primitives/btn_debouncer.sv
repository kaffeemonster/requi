module btn_debouncer #(
    parameter real DEBOUNCE_MS = 10.0,
    parameter real CLK_FREQ_MHZ = 50.0
)(
    input  wire clk,
    input  wire rst_n,
    input  wire button_in,
    output wire button_out
);

    localparam int COUNTER_MAX = int'(DEBOUNCE_MS * CLK_FREQ_MHZ * 1000.0);
    localparam int COUNTER_WIDTH = $clog2(COUNTER_MAX);

    // --------------------------------------------------------------------
    // 1. Synchronisation
    // --------------------------------------------------------------------
    logic sync_ff1, sync_ff2;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            sync_ff1 <= 1'b1;
            sync_ff2 <= 1'b1;
        end else begin
            sync_ff1 <= button_in;
            sync_ff2 <= sync_ff1;
        end
    end

    logic [COUNTER_WIDTH-1:0] counter;
    logic stable_state;
    logic counter_zero;

    assign counter_zero = (counter == 0);

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            counter      <= COUNTER_MAX - 1;
            stable_state <= 1'b1;
        end else begin
            if (sync_ff2 != stable_state) begin
                counter      <= COUNTER_MAX - 1;  // Reset auf MAX
                stable_state <= sync_ff2;
            end
            else if (!counter_zero) begin
                counter <= counter - 1;           // Dekrement
            end
            // Bei counter_zero: Zähler bleibt stehen
        end
    end

    // --------------------------------------------------------------------
    // 3. Ausgang
    // --------------------------------------------------------------------
    logic button_out_ff;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            button_out_ff <= 1'b1;
        end else begin
            if (counter_zero)
                button_out_ff <= stable_state;
        end
    end

    assign button_out = button_out_ff;

endmodule
