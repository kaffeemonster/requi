`ifdef CORE_CORE_TYPES_H
` define CORE_CORE_TYPES_H 1

typedef struct packed {
    logic zero;      // Bit 3
    logic overflow;  // Bit 2
    logic negative;  // Bit 1
    logic carry;     // Bit 0
} alu_flags_t;

`endif