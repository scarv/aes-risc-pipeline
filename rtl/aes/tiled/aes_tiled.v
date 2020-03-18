
//
// AES proposal: tiled
//
module aes_tiled (
input   wire        g_clk   ,
input   wire        g_resetn,
input   wire        valid   , // Input data valid
input   wire        dec     , // Encrypt (0) or decrypt (1)
input   wire        op_sb   , // Sub-bytes only
input   wire        op_sbsr , // Subbytes and shift-rows
input   wire        op_mix  , // Mix-Columns
input   wire        hi      , // High or low shiftrows?
input   wire [31:0] rs1     , // Input source register
input   wire [31:0] rs2     , // Input source register

output  wire        ready   , // Finished computing?
output  wire [31:0] rd        // Output destination register value.
);

`define BYTEOF(X,I) X[7+8*I:8*I]

// Sub-bytes input/output
wire [ 7:0] sbin_0 ,sbin_1 ,sbin_2 ,sbin_3 ;
wire [ 7:0] sbout_0,sbout_1,sbout_2,sbout_3;

// Mix columns input/output
wire [ 7:0] mi0_0, mi0_1, mi0_2, mi0_3;
wire [ 7:0] mi1_0, mi1_1, mi1_2, mi1_3;
wire [ 7:0] mo0_0, mo0_1;
wire [ 7:0] mo1_0, mo1_1;

// Everything completes in a single cycle.
assign      ready  = valid;

//
// SubBytes/ShiftRows selections.
// ------------------------------------------------------------

wire [ 7:0] sbsr_sbin_0 = hi    ? `BYTEOF(rs2,2) : `BYTEOF(rs1,2)   ;
wire [ 7:0] sbsr_sbin_1 = hi    ? `BYTEOF(rs2,1) : `BYTEOF(rs1,0)   ;
wire [ 7:0] sbsr_sbin_2 = hi    ? `BYTEOF(rs2,0) : `BYTEOF(rs1,1)   ;
wire [ 7:0] sbsr_sbin_3 = hi    ? `BYTEOF(rs1,3) : `BYTEOF(rs2,3)   ;

assign      sbin_0      = op_sb ? `BYTEOF(rs1,0) :  sbsr_sbin_0     ;
assign      sbin_1      = op_sb ? `BYTEOF(rs1,1) :  sbsr_sbin_1     ;
assign      sbin_2      = op_sb ? `BYTEOF(rs1,2) :  sbsr_sbin_2     ;
assign      sbin_3      = op_sb ? `BYTEOF(rs1,3) :  sbsr_sbin_3     ;

wire [31:0] result_sbsr = {sbout_3, sbout_2, sbout_1, sbout_0}; 

//
// MixColumn selections.
// ------------------------------------------------------------

assign      mi0_3       = `BYTEOF(rs1,2);
assign      mi0_2       = `BYTEOF(rs1,3);
assign      mi0_1       = `BYTEOF(rs2,2);
assign      mi0_0       = `BYTEOF(rs2,3);
assign      mi1_3       = `BYTEOF(rs1,0);
assign      mi1_2       = `BYTEOF(rs1,1);
assign      mi1_1       = `BYTEOF(rs2,0);
assign      mi1_0       = `BYTEOF(rs2,1);

wire [31:0] mc_0        = {mi0_3, mi0_2, mi0_1, mi0_0};
wire [31:0] mc_1        = {mi1_3, mi1_2, mi1_1, mi1_0};
wire [31:0] mc_0r       = {mi0_2, mi0_1, mi0_0, mi0_3};
wire [31:0] mc_1r       = {mi1_2, mi1_1, mi1_0, mi1_3};

wire [31:0] result_mix  = {mo1_0, mo1_1, mo0_0, mo0_1};

//
// Result multiplexing
// ------------------------------------------------------------

assign  rd              = op_mix ? result_mix : result_sbsr;

//
// Submodule instances
// ------------------------------------------------------------

aes_sbox i_aes_sbox_0(.in (sbin_0), .inv(dec  ), .out(sbout_0) );
aes_sbox i_aes_sbox_1(.in (sbin_1), .inv(dec  ), .out(sbout_1) );
aes_sbox i_aes_sbox_2(.in (sbin_2), .inv(dec  ), .out(sbout_2) );
aes_sbox i_aes_sbox_3(.in (sbin_3), .inv(dec  ), .out(sbout_3) );

aes_mixcolumn_byte i_aes_mixcolumn_0 (.col_in(mc_0 ), .dec(dec), .byte_out(mo0_0));
aes_mixcolumn_byte i_aes_mixcolumn_1 (.col_in(mc_1 ), .dec(dec), .byte_out(mo1_0));
aes_mixcolumn_byte i_aes_mixcolumn_2 (.col_in(mc_0r), .dec(dec), .byte_out(mo0_1));
aes_mixcolumn_byte i_aes_mixcolumn_3 (.col_in(mc_1r), .dec(dec), .byte_out(mo1_1));

`undef BYTEOF

endmodule
