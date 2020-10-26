
//
// AES proposal: tiled
//
module aes_tiled_size (
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

// Enable the decryption instructions.
parameter DECRYPT_EN=1;

wire   decrypt = dec && DECRYPT_EN;

`define BYTEOF(X,I) X[7+8*I:8*I]

// Sub-bytes input/output
wire [ 7:0] sbinf_0 ,sbinf_1 ,sbinf_2 ,sbinf_3 ;
wire [ 7:0] sbini_0 ,sbini_1 ,sbini_2 ,sbini_3 ;
wire [ 7:0] sbfwd_out;
wire [ 7:0] sbinv_out;

// Mix columns input/output
wire [ 7:0] mi0_0, mi0_1, mi0_2, mi0_3;
wire [ 7:0] mi1_0, mi1_1, mi1_2, mi1_3;
wire [ 7:0] mix_out;

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

assign      sbini_0     = hi    ? `BYTEOF(rs2,2) : `BYTEOF(rs1,2)   ;
assign      sbini_1     = hi    ? `BYTEOF(rs1,1) : `BYTEOF(rs1,0)   ;
assign      sbini_2     = hi    ? `BYTEOF(rs2,0) : `BYTEOF(rs2,1)   ;
assign      sbini_3     = hi    ? `BYTEOF(rs2,3) : `BYTEOF(rs1,3)   ;

wire [31:0] sbsr_fwd    =  hi ? {t1, t0, sbfwd_out, t2}: 
                                {t2, t0, sbfwd_out, t1}; 
                                                                   
wire [31:0] sbsr_inv    =  hi ? {t1, t0, sbinv_out, t2}: 
                                {t2, t0, sbinv_out, t1}; 

wire [31:0] result_sbsr = decrypt ? sbsr_inv : sbsr_fwd;
wire [31:0] result_sb   = {sbfwd_out, t2, t1, t0}; 

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

wire [31:0] result_mix  = {t2, t0, mix_out, t1};


//
// Control FSM
// ------------------------------------------------------------

reg [  1:0]   fsm;
reg [  1:0] n_fsm;

localparam  FSM_IDLE    = 2'b00;
localparam  FSM_S1      = 2'b01;
localparam  FSM_S2      = 2'b10;
localparam  FSM_S3      = 2'b11;

wire        fsm_idle    = fsm == FSM_IDLE;
wire        fsm_s1      = fsm == FSM_S1  ;
wire        fsm_s2      = fsm == FSM_S2  ;
wire        fsm_s3      = fsm == FSM_S3  ;

assign      ready       = fsm_s3;

always @(*) case(fsm)
    FSM_IDLE : n_fsm = valid ? FSM_S1 : FSM_IDLE;
    FSM_S1   : n_fsm = FSM_S2;
    FSM_S2   : n_fsm = FSM_S3;
    FSM_S3   : n_fsm = FSM_IDLE;
endcase

always @(posedge g_clk) begin
    if(!g_resetn) begin
        fsm <= 2'b00;
    end else begin
        fsm <= n_fsm;
    end
end

reg [7:0] r0, r1, r2;

//
// Temporary Storage
// ------------------------------------------------------------

reg  [  7:0] t0;
reg  [  7:0] t1;
reg  [  7:0] t2;

wire         n_tmp_sub_fwd = (op_sb || op_sbsr) && !decrypt;
wire         n_tmp_sub_inv = (         op_sbsr) &&  decrypt;
wire         n_tmp_mix     = (op_mix          );

wire [  7:0] n_tmp         = {8{n_tmp_sub_fwd}} & sbfwd_out    |
                             {8{n_tmp_sub_inv}} & sbinv_out    |
                             {8{n_tmp_mix    }} & mix_out      ;

always @(posedge g_clk) if(fsm_idle && valid) t0 <= n_tmp;
always @(posedge g_clk) if(fsm_s1           ) t1 <= n_tmp;
always @(posedge g_clk) if(fsm_s2           ) t2 <= n_tmp;

//
// Result multiplexing
// ------------------------------------------------------------

assign  rd              = op_mix ? result_mix  :
                          op_sb  ? result_sb   :
                                   result_sbsr ;

//
// Submodule instances
// ------------------------------------------------------------

wire [7:0] sbfwd_in = 
    {8{fsm_idle}} & sbinf_0 |
    {8{fsm_s1  }} & sbinf_1 |
    {8{fsm_s2  }} & sbinf_2 |
    {8{fsm_s3  }} & sbinf_3 ;

wire [7:0] sbinv_in = 
    {8{fsm_idle}} & sbini_0 |
    {8{fsm_s1  }} & sbini_1 |
    {8{fsm_s2  }} & sbini_2 |
    {8{fsm_s3  }} & sbini_3 ;

aes_fwd_sbox i_aes_sbox_f0(.in (sbfwd_in), .fx(sbfwd_out) );

generate if(DECRYPT_EN) begin:decrypt_enabled
    aes_inv_sbox i_aes_sbox_i0(.in (sbinv_in), .fx(sbinv_out) );
end else begin : decrypt_disabled
    assign sbinv_out = 8'b0;
end endgenerate

wire [31:0] mix_in =
    {32{fsm_idle}} & mc_0  |
    {32{fsm_s1  }} & mc_1  |
    {32{fsm_s2  }} & mc_0r |
    {32{fsm_s3  }} & mc_1r ;

aes_mixcolumn_byte i_aes_mixcolumn_0 (.col_in(mix_in), .dec(decrypt), .byte_out(mix_out));

`undef BYTEOF

endmodule
