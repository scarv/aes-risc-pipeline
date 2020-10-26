
//
// AES proposal: Variant 1
//
//  Optimised to be as small as possible.
//  Instances 1 SBox, takes 4 cycles.
//
module aes_v1_size (
input   wire        g_clk   ,
input   wire        g_resetn,
input   wire        valid   , // Input data valid
input   wire        dec     , // Encrypt (0) or decrypt (1)
input   wire        mix     , // Do MixColumns (1) or SubBytes (0)
input   wire [31:0] rs1     , // Input source register

output  wire        ready   , // Finished computing?
output  wire [31:0] rd        // Output destination register value.
);

// Enable the decryption instructions.
parameter DECRYPT_EN=1;

localparam FSM_IDLE = 3'd0;
localparam FSM_B0   = 3'd1;
localparam FSM_B1   = 3'd2;
localparam FSM_B2   = 3'd3;
localparam FSM_B3   = 3'd4;

reg  [ 2:0]   fsm       ;
reg  [ 2:0] n_fsm       ;

wire [ 7:0] sb_in       ;
wire [ 7:0] sb_out      ;

wire        decrypt     = dec && DECRYPT_EN;

// Intermediate value storage registers.
reg  [ 7:0] r0, r1, r2, r3;

wire [31:0] result_sb   = {r3, r2, r1, r0};
wire [31:0] result_mc   ;

assign      rd          = mix ? result_mc : result_sb;

// Shift down RS1 per byte to get input to SBOX.
/* verilator lint_off WIDTH */
assign      sb_in       =  rs1 >> {fsm,3'b000}       ;
/* verilator lint_on WIDTH */

// Have we finished computing every SBOX?
assign      ready       =  
    mix ? 1'b1 : fsm == FSM_B3            ;

// Intermediate value load enable registers.
wire        r0_ld_en    = (fsm == FSM_IDLE) && valid;
wire        r1_ld_en    = (fsm == FSM_B0  )         ;
wire        r2_ld_en    = (fsm == FSM_B1  )         ;
wire        r3_ld_en    = (fsm == FSM_B2  )         ;

//
// FSM Next state.
always @(*) begin
    case(fsm)
        FSM_IDLE: n_fsm = valid && !mix ? FSM_B0 : FSM_IDLE;
        FSM_B0  : n_fsm = FSM_B1;
        FSM_B1  : n_fsm = FSM_B2;
        FSM_B2  : n_fsm = FSM_B3;
        FSM_B3  : n_fsm = FSM_IDLE;
        default : n_fsm = FSM_IDLE;
    endcase
end

//
// FSM State register progression.
always @(posedge g_clk) begin
    if(!g_resetn) begin
        fsm <= FSM_IDLE;
    end else begin
        fsm <= n_fsm   ;
    end
end

//
// Intermediate value storage registers.
always @(posedge g_clk) begin
    if(!g_resetn) begin
        r0 <= 8'b0;
        r1 <= 8'b0;
        r2 <= 8'b0;
        r3 <= 8'b0;
    end else begin
        if(r0_ld_en) r0 <= sb_out ;
        if(r1_ld_en) r1 <= sb_out ;
        if(r2_ld_en) r2 <= sb_out ;
        if(r3_ld_en) r3 <= sb_out ;
    end
end

//
// Single SBOX instance.
aes_sbox #(.DECRYPT_EN(DECRYPT_EN)) i_aes_sbox(
.in (sb_in ),
.inv(decrypt),
.out(sb_out)
);

aes_mixcolumn  #(.DECRYPT_EN(DECRYPT_EN))i_aes_mixcolumn(
    .col_in(rs1), .dec(decrypt), .col_out(result_mc)
);

endmodule
