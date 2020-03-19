
//
// AES proposal: tiled
//
module aes_tiled (
input   wire        g_clk       ,
input   wire        g_resetn    ,
input   wire        valid       , // Input data valid
input   wire        dec         , // Encrypt (0) or decrypt (1)
input   wire        op_sb       , // Sub-bytes only
input   wire        op_sbsr     , // Subbytes and shift-rows
input   wire        op_mix      , // Mix-Columns
input   wire        hi          , // High or low shiftrows?
input   wire [31:0] rs1         , // Input source register
input   wire [31:0] rs2         , // Input source register

output  wire        ready       , // Finished computing?
output  wire [31:0] rd            // Output destination register value.
);

`define BYTEOF(X,I) X[7+8*I:8*I]

// Sub-bytes input/output
wire [ 7:0] sbinf_0 ,sbinf_1 ,sbinf_2 ,sbinf_3 ;
wire [ 7:0] sbini_0 ,sbini_1 ,sbini_2 ,sbini_3 ;
wire [ 7:0] sbfwd_0,sbfwd_1,sbfwd_2,sbfwd_3;
wire [ 7:0] sbinv_0,sbinv_1,sbinv_2,sbinv_3;

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

assign      sbinf_0     = op_sb ? `BYTEOF(rs1,0) :  sbsr_sbin_0     ;
assign      sbinf_1     = op_sb ? `BYTEOF(rs1,1) :  sbsr_sbin_1     ;
assign      sbinf_2     = op_sb ? `BYTEOF(rs1,2) :  sbsr_sbin_2     ;
assign      sbinf_3     = op_sb ? `BYTEOF(rs1,3) :  sbsr_sbin_3     ;

assign      sbini_0     =                           sbsr_sbin_0     ;
assign      sbini_1     =                           sbsr_sbin_1     ;
assign      sbini_2     =                           sbsr_sbin_2     ;
assign      sbini_3     =                           sbsr_sbin_3     ;

wire [31:0] sbsr_fwd    =  hi ? {sbfwd_2, sbfwd_3, sbfwd_0, sbfwd_1}: 
                                {sbfwd_1, sbfwd_3, sbfwd_0, sbfwd_2}; 

wire [31:0] sbsr_inv    =  hi ? {sbinv_2, sbinv_3, sbinv_0, sbinv_1}: 
                                {sbinv_1, sbinv_3, sbinv_0, sbinv_2}; 

wire [31:0] result_sbsr = dec ? sbsr_inv : sbsr_fwd;
wire [31:0] result_sb   = {sbfwd_3, sbfwd_2, sbfwd_1, sbfwd_0}; 

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

assign  rd              = op_mix ? result_mix  :
                          op_sb  ? result_sb   :
                                   result_sbsr ;

//
// Submodule instances
// ------------------------------------------------------------

aes_fwd_sbox i_aes_sbox_f0(.in (sbinf_0), .fx(sbfwd_0) );
aes_fwd_sbox i_aes_sbox_f1(.in (sbinf_1), .fx(sbfwd_1) );
aes_fwd_sbox i_aes_sbox_f2(.in (sbinf_2), .fx(sbfwd_2) );
aes_fwd_sbox i_aes_sbox_f3(.in (sbinf_3), .fx(sbfwd_3) );

aes_inv_sbox i_aes_sbox_i0(.in (sbini_0), .fx(sbinv_0) );
aes_inv_sbox i_aes_sbox_i1(.in (sbini_1), .fx(sbinv_1) );
aes_inv_sbox i_aes_sbox_i2(.in (sbini_2), .fx(sbinv_2) );
aes_inv_sbox i_aes_sbox_i3(.in (sbini_3), .fx(sbinv_3) );

aes_mixcolumn_byte i_aes_mixcolumn_0 (.col_in(mc_0 ), .dec(dec), .byte_out(mo0_0));
aes_mixcolumn_byte i_aes_mixcolumn_1 (.col_in(mc_1 ), .dec(dec), .byte_out(mo1_0));
aes_mixcolumn_byte i_aes_mixcolumn_2 (.col_in(mc_0r), .dec(dec), .byte_out(mo0_1));
aes_mixcolumn_byte i_aes_mixcolumn_3 (.col_in(mc_1r), .dec(dec), .byte_out(mo1_1));

`undef BYTEOF

endmodule
