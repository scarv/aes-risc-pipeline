
//
// AES proposal: Variant 1
//
//  Optimised to execute in a minimum number of cycles: 1.
//  Instances four separate SBoxes.
//
module aes_v1_latency (
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

wire decrypt = DECRYPT_EN && dec;

wire [7:0] rs1_0, rs1_1, rs1_2, rs1_3;
wire [7:0] rd_0 , rd_1 , rd_2 , rd_3 ;

assign ready                        = valid;

assign {rs1_3, rs1_2, rs1_1, rs1_0} = rs1;

wire [31:0] result_subbytes         = {rd_3, rd_2, rd_1, rd_0};
wire [31:0] result_mixcols          ;

assign rd = mix ? result_mixcols : result_subbytes;
        
aes_sbox #(.DECRYPT_EN(DECRYPT_EN)) i_aes_sbox_0(.in (rs1_0), .inv(decrypt), .out( rd_0) );
aes_sbox #(.DECRYPT_EN(DECRYPT_EN)) i_aes_sbox_1(.in (rs1_1), .inv(decrypt), .out( rd_1) );
aes_sbox #(.DECRYPT_EN(DECRYPT_EN)) i_aes_sbox_2(.in (rs1_2), .inv(decrypt), .out( rd_2) );
aes_sbox #(.DECRYPT_EN(DECRYPT_EN)) i_aes_sbox_3(.in (rs1_3), .inv(decrypt), .out( rd_3) );

aes_mixcolumn #(.DECRYPT_EN(DECRYPT_EN)) i_aes_mixcolumn(
    .col_in(rs1), .dec(decrypt), .col_out(result_mixcols)
);

endmodule
