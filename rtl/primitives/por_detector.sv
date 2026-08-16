module por_detector (
    input logic clk,                 // Ihr Systemtakt
    output logic por_reset_n = 0 // Startet hardwareseitig als 0 (aktiv)
);

    // Initialisierung mit 4'b1111 zwingt das FPGA, diese Register beim Booten auf HIGH zu setzen.
    // Das entspricht Ihrem "GSR-Ersatz".
    logic [4:0] clk_div   = 4'b1111;
    logic [3:0] delay_reg = 4'b1111;

    always_ff @(posedge clk) begin
        clk_div <= clk_div - 1;
    end

    always_ff @(posedge (clk_div == 4'b0)) begin
        // Schiebt nach dem Booten Nullen von rechts nach links rein
        delay_reg <= {delay_reg[2:0], 1'b0};

        // Sobald alle Einsen rausgeschoben wurden, geht por_reset_n dauerhaft auf 1 (bereit)
        if (delay_reg == 4'b0000) begin
            por_reset_n <= 1'b1;
        end else begin
            por_reset_n <= 1'b0;
        end
    end

endmodule

