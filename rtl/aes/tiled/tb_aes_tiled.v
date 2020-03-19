
//
// Model checker for tiled AES instructions.
//
module tb_aes_tiled(
input   g_clk       ,
input   g_resetn
);

//
// Useful common stuff
// ------------------------------------------------------------

`include "aes_functions.vh"

`define BYTE(X,I) X[7+8*I:8*I]

//
// DUT Interface
// ------------------------------------------------------------

//
// DUT Inputs
reg         dut_valid   = $anyseq; // Input data valid
reg         dut_dec     = $anyseq; // Encrypt (0) or decrypt (1)
reg         dut_op_sb   = $anyseq; // Sub-bytes only
reg         dut_op_sbsr = $anyseq; // Subbytes and shift-rows
reg         dut_op_mix  = $anyseq; // Mix-Columns
reg         dut_hi      = $anyseq; // High or low shiftrows?
reg  [31:0] dut_rs1     = $anyseq; // Input source register
reg  [31:0] dut_rs2     = $anyseq; // Input source register

wire        dut_ready   ; // Finished computing?
wire [31:0] dut_rd      ; // Output destination register value.


//
// Golden Reference
// ------------------------------------------------------------

//
// SubBytes & Shift Rows
wire [ 7:0] sub_t0 = dut_hi ? `BYTE(dut_rs2, 2) : `BYTE(dut_rs1,2);
wire [ 7:0] sub_t1 = dut_hi ? `BYTE(dut_rs2, 1) : `BYTE(dut_rs1,0);
wire [ 7:0] sub_t2 = dut_hi ? `BYTE(dut_rs2, 0) : `BYTE(dut_rs1,1);
wire [ 7:0] sub_t3 = dut_hi ? `BYTE(dut_rs1, 3) : `BYTE(dut_rs2,3);

wire [ 7:0] sub_f0 = aes_sbox_fwd(sub_t0);
wire [ 7:0] sub_f1 = aes_sbox_fwd(sub_t1);
wire [ 7:0] sub_f2 = aes_sbox_fwd(sub_t2);
wire [ 7:0] sub_f3 = aes_sbox_fwd(sub_t3);

wire [ 7:0] sub_i0 = aes_sbox_inv(sub_t0);
wire [ 7:0] sub_i1 = aes_sbox_inv(sub_t1);
wire [ 7:0] sub_i2 = aes_sbox_inv(sub_t2);
wire [ 7:0] sub_i3 = aes_sbox_inv(sub_t3);

wire [31:0] sbsr_fwd_hi = {sub_f2, sub_f3, sub_f0, sub_f1};
wire [31:0] sbsr_fwd_lo = {sub_f1, sub_f3, sub_f0, sub_f2};

wire [31:0] sbsr_inv_hi = {sub_i2, sub_i3, sub_i0, sub_i1};
wire [31:0] sbsr_inv_lo = {sub_i1, sub_i3, sub_i0, sub_i2};

//
// MixColumns

wire [31:0] col_0 = {`BYTE(dut_rs1,2), `BYTE(dut_rs1,3), `BYTE(dut_rs2,2), `BYTE(dut_rs2,3)};
wire [31:0] col_1 = {`BYTE(dut_rs1,0), `BYTE(dut_rs1,1), `BYTE(dut_rs2,0), `BYTE(dut_rs2,1)};

wire [ 7:0] e_n0  = mixcolumn_byte_enc2( col_0                     );
wire [ 7:0] e_n1  = mixcolumn_byte_enc2({col_0[23:0], col_0[31:24]});
wire [ 7:0] e_n2  = mixcolumn_byte_enc2( col_1                     );
wire [ 7:0] e_n3  = mixcolumn_byte_enc2({col_1[23:0], col_1[31:24]});

wire [ 7:0] d_n0  = mixcolumn_byte_dec2( col_0                     );
wire [ 7:0] d_n1  = mixcolumn_byte_dec2({col_0[23:0], col_0[31:24]});
wire [ 7:0] d_n2  = mixcolumn_byte_dec2( col_1                     );
wire [ 7:0] d_n3  = mixcolumn_byte_dec2({col_1[23:0], col_1[31:24]});

wire [31:0] mix_enc = {e_n2, e_n3, e_n0, e_n1};
wire [31:0] mix_dec = {d_n2, d_n3, d_n0, d_n1};

// Just apply sub-bytes to each element of rs1.
wire [31:0] result_sb   = {
    aes_sbox_fwd(`BYTE(dut_rs1, 3)),
    aes_sbox_fwd(`BYTE(dut_rs1, 2)),
    aes_sbox_fwd(`BYTE(dut_rs1, 1)),
    aes_sbox_fwd(`BYTE(dut_rs1, 0))
};

wire [31:0] result_sbsr = 
    !dut_dec && !dut_hi ? sbsr_fwd_lo   :
    !dut_dec &&  dut_hi ? sbsr_fwd_hi   :
     dut_dec && !dut_hi ? sbsr_inv_lo   :
     dut_dec &&  dut_hi ? sbsr_inv_hi   : 0 ;

wire [31:0] result_mix  = dut_dec ? mix_dec : mix_enc;

//
// Assertions and Assumptions
// ------------------------------------------------------------


// Assume we start in reset...
initial assume(!g_resetn);

//
// Formal Cover statements
always @(posedge g_clk) if(g_resetn) begin

    // Do we ever run anything?
    cover(dut_valid             );

    // Do we ever finish?
    cover(dut_valid && dut_ready);

end

//
// Formal assumptions
always @(posedge g_clk) begin

    //
    // Constraints
    if($past(dut_valid) && $past(!dut_ready)) begin
        // If the TB is waiting for the DUT to compute an output,
        // make sure that the inputs are stable.
        assume($stable(dut_valid  ));
        assume($stable(dut_dec    ));
        assume($stable(dut_op_sb  ));
        assume($stable(dut_op_sbsr));
        assume($stable(dut_op_mix ));
        assume($stable(dut_hi     ));
        assume($stable(dut_rs1    ));
        assume($stable(dut_rs2    ));
        
        // Atlease one op should be set!
        assume(|{dut_op_sb,dut_op_sbsr, dut_op_mix});

    end
        
    // Assume one-hotness of input op commands.
    assume(
        {dut_op_sb,dut_op_sbsr, dut_op_mix} == 3'b100 ||
        {dut_op_sb,dut_op_sbsr, dut_op_mix} == 3'b010 ||
        {dut_op_sb,dut_op_sbsr, dut_op_mix} == 3'b001
    );

end


//
// Formal checks
always @(posedge g_clk) begin

    if(g_resetn && dut_valid && dut_ready) begin

        if(dut_op_sb) begin
            
            assert(dut_rd == result_sb);

        end else if(dut_op_sbsr) begin
            
            assert(dut_rd == result_sbsr);

        end else if(dut_op_mix) begin
            
            assert(dut_rd == result_mix);

        end
    end
    

end

//
// Submodule Instances
// ------------------------------------------------------------

`undef BYTE

//
// Instance the DUT
//
aes_tiled i_dut (
.g_clk   (g_clk         ),
.g_resetn(g_resetn      ),
.valid   (dut_valid     ), // Input data valid
.dec     (dut_dec       ), // Encrypt (0) or decrypt (1)
.op_sb   (dut_op_sb     ), // Sub-bytes only
.op_sbsr (dut_op_sbsr   ), // Subbytes and shift-rows
.op_mix  (dut_op_mix    ), // Mix-Columns
.hi      (dut_hi        ), // High or low shiftrows?
.rs1     (dut_rs1       ), // Input source register
.rs2     (dut_rs2       ), // Input source register
.ready   (dut_ready     ), // Finished computing?
.rd      (dut_rd        )  // Output destination register value.
);


endmodule

