package axi4_pkg;

    // ========================================================================
    // 1. ENUMS (Protokoll-Typen)
    // ========================================================================

    // Burst Types (awburst / arburst)
    typedef enum logic [1:0] {
        AXI_BURST_FIXED    = 2'b00, // FIFO / Stream-Register
        AXI_BURST_INCR     = 2'b01, // Normaler Speicher/DMA-Transfer
        AXI_BURST_WRAP     = 2'b10, // Cache Line Fill
        AXI_BURST_RESERVED = 2'b11  // Ungültig nach AXI-Spezifikation
    } axi_burst_t;

    // Response Status (bresp / rresp)
    typedef enum logic [1:0] {
        AXI_RESP_OKAY   = 2'b00, // Normaler erfolgreicher Zugriff
        AXI_RESP_EXOKAY = 2'b01, // Exclusive Access gestattet/erfolgreich
        AXI_RESP_SLVERR = 2'b10, // Fehler auf Slave-Seite (z.B. ungültige Adresse)
        AXI_RESP_DECERR = 2'b11  // Interconnect Decode Error (kein Slave unter Adresse)
    } axi_resp_t;

    // Atomic Lock Types (awlock / arlock)
    typedef enum logic {
        AXI_LOCK_NORMAL    = 1'b0, // Normaler Zugriff
        AXI_LOCK_EXCLUSIVE = 1'b1  // Exklusiver Zugriff (z.B. Atomic Swap/RMW)
    } axi_lock_t;

    // Transfer Size Encoding (awsize / arsize)
    typedef enum logic [2:0] {
        AXI_SIZE_1B   = 3'b000, // 1 Byte  (8 Bit)
        AXI_SIZE_2B   = 3'b001, // 2 Bytes (16 Bit)
        AXI_SIZE_4B   = 3'b010, // 4 Bytes (32 Bit)
        AXI_SIZE_8B   = 3'b011, // 8 Bytes (64 Bit)
        AXI_SIZE_16B  = 3'b100, // 16 Bytes (128 Bit)
        AXI_SIZE_32B  = 3'b101, // 32 Bytes (256 Bit)
        AXI_SIZE_64B  = 3'b110, // 64 Bytes (512 Bit)
        AXI_SIZE_128B = 3'b111  // 128 Bytes (1024 Bit)
    } axi_size_t;

    // ========================================================================
    // 2. STRUCTS (Optionale Field-Decoder für Cache & Protection)
    // ========================================================================

    // Protection Field Bit-Layout (awprot / arprot)
    typedef struct packed {
        logic instruction; // 0 = Data, 1 = Instruction
        logic non_secure;  // 0 = Secure, 1 = Non-Secure (TrustZone)
        logic privileged;  // 0 = Unprivileged (User), 1 = Privileged
    } axi_prot_t;

    // Cache Attribute Bit-Layout (awcache / arcache)
    typedef struct packed {
        logic allocate;    // Allocate on miss
        logic other_alloc; // Other-allocate
        logic modifiable;  // Modifiable (Transfer darf geteilt/zusammengefasst werden)
        logic bufferable;  // Bufferable (Write Response darf frühzeitig kommen)
    } axi_cache_t;
    
    // 4-Bit QoS Vektor
    typedef logic [3:0] axi_qos_t;
    // Optional: Standard-Stufen als Enum/Konstanten
    typedef enum logic [3:0] {
        AXI_QOS_LOWEST    = 4'b0000,
        AXI_QOS_MEDIUM    = 4'b1000,
        AXI_QOS_HIGH      = 4'b1100,
        AXI_QOS_REALTIME  = 4'b1111
    } axi_qos_level_t;
    // Standard-Prioritäten für QoS
    localparam axi_qos_t AXI_QOS_DEFAULT   = 4'b0000;
    localparam axi_qos_t AXI_QOS_BEST_EFFORT = 4'b0000;
    localparam axi_qos_t AXI_QOS_LATENCY_SENSITIVE = 4'b1000;
    localparam axi_qos_t AXI_QOS_HIGHEST     = 4'b1111;

    // 4-Bit Region Identifier
    typedef logic [3:0] axi_region_t;

    // ========================================================================
    // 3. HELPER FUNCTIONS
    // ========================================================================


    // Parametrisierte Helper-Klasse
    class axi_helpers #(
        parameter ADDR_WIDTH = 32,
        parameter DATA_WIDTH = 32
    );
        localparam STRB_WIDTH = DATA_WIDTH / 8;

        // ------------------------------------------------------------------------
        // A) Konvertiert axi_size_t Enum in die tatsächliche Anzahl an Bytes (2^size)
        // ------------------------------------------------------------------------
        static function logic[ADDR_WIDTH:0] size_to_bytes(input axi_size_t size);
            return (1 << size);
        endfunction

        // ------------------------------------------------------------------------
        // B) Berechnet die Folgeadresse für den nächsten Beat
        // ------------------------------------------------------------------------
        static function logic [ADDR_WIDTH-1:0] get_next_addr (
            input logic [ADDR_WIDTH-1:0] current_addr,
            input axi_burst_t            burst_type,
            input axi_size_t             burst_size,
            input logic [7:0]            burst_len
        );
            logic [ADDR_WIDTH-1:0] number_bytes = size_to_bytes(burst_size);
            logic [ADDR_WIDTH-1:0] total_burst_bytes;
            logic [ADDR_WIDTH-1:0] wrap_boundary_mask;

            case (burst_type)
                AXI_BURST_FIXED: return current_addr;
                AXI_BURST_INCR:  return current_addr + number_bytes;
                AXI_BURST_WRAP: begin
                    total_burst_bytes  = (burst_len + 1) * number_bytes;
                    wrap_boundary_mask = total_burst_bytes - 1;
                    return (current_addr & ~wrap_boundary_mask) | 
                           ((current_addr + number_bytes) & wrap_boundary_mask);
                end
                default: return current_addr + number_bytes;
            endcase
        endfunction

        // ------------------------------------------------------------------------
        // C) Berechnet die Folgeadresse für den nächsten Beat, ignoriert wrap
        // ------------------------------------------------------------------------
        static function logic [ADDR_WIDTH-1:0] get_next_addr_nowrap (
            input logic [ADDR_WIDTH-1:0] current_addr,
            input axi_burst_t            burst_type,
            input axi_size_t             burst_size,
            input logic [7:0]            burst_len
        );
            logic [ADDR_WIDTH-1:0] number_bytes = size_to_bytes(burst_size);
            logic [ADDR_WIDTH-1:0] total_burst_bytes;
            logic [ADDR_WIDTH-1:0] wrap_boundary_mask;

            case (burst_type)
                AXI_BURST_FIXED: return current_addr;
                AXI_BURST_INCR:  return current_addr + number_bytes;
                default: return current_addr + number_bytes;
            endcase
        endfunction

        static function logic [STRB_WIDTH-1:0] get_wstrb (
            input logic [ADDR_WIDTH-1:0] addr,
            input axi_size_t             size
        );
            logic [STRB_WIDTH-1:0] mask;
            integer bytes       = 1 << size;
            integer addr_offset = addr % STRB_WIDTH;

            mask = (1 << bytes) - 1;
            return (mask << addr_offset);
        endfunction

        // ------------------------------------------------------------------------
        // C) Berechnet das wstrb (Byte Enable) Bitmuster basierend auf Adresse & Größe
        // ------------------------------------------------------------------------
        static function logic [DATA_WIDTH-1:0] get_wstrb_msk (
            input logic [ADDR_WIDTH-1:0] addr,
            input axi_size_t   size,
            input integer      data_width_bits // z.B. 32, 64, 128, 256
        );
            logic [DATA_WIDTH:0] mask;
            integer bytes;
            integer data_width_bytes;
            integer addr_offset;

            bytes            = size_to_bytes(size);
            data_width_bytes = data_width_bits / 8;
            addr_offset      = addr % data_width_bytes; // Lower Bits
        
            // Grundmaske für die Byte-Anzahl erzeugen (z.B. size=2B -> 2'b11)
            mask = (1 << bytes) - 1;
        
            // Auf die korrekte Byte-Lane im Bus verschieben
            return (mask << addr_offset);
        endfunction
        
    endclass

endpackage: axi4_pkg
