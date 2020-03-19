
function [7:0] aes_sbox_fwd;
    input [7:0] sbin;

    case(sbin)
        0  : aes_sbox_fwd = 8'h63;
        1  : aes_sbox_fwd = 8'h7c;
        2  : aes_sbox_fwd = 8'h77;
        3  : aes_sbox_fwd = 8'h7b;
        4  : aes_sbox_fwd = 8'hf2;
        5  : aes_sbox_fwd = 8'h6b;
        6  : aes_sbox_fwd = 8'h6f;
        7  : aes_sbox_fwd = 8'hc5;
        8  : aes_sbox_fwd = 8'h30;
        9  : aes_sbox_fwd = 8'h01;
        10 : aes_sbox_fwd = 8'h67;
        11 : aes_sbox_fwd = 8'h2b;
        12 : aes_sbox_fwd = 8'hfe;
        13 : aes_sbox_fwd = 8'hd7;
        14 : aes_sbox_fwd = 8'hab;
        15 : aes_sbox_fwd = 8'h76;
        16 : aes_sbox_fwd = 8'hca;
        17 : aes_sbox_fwd = 8'h82;
        18 : aes_sbox_fwd = 8'hc9;
        19 : aes_sbox_fwd = 8'h7d;
        20 : aes_sbox_fwd = 8'hfa;
        21 : aes_sbox_fwd = 8'h59;
        22 : aes_sbox_fwd = 8'h47;
        23 : aes_sbox_fwd = 8'hf0;
        24 : aes_sbox_fwd = 8'had;
        25 : aes_sbox_fwd = 8'hd4;
        26 : aes_sbox_fwd = 8'ha2;
        27 : aes_sbox_fwd = 8'haf;
        28 : aes_sbox_fwd = 8'h9c;
        29 : aes_sbox_fwd = 8'ha4;
        30 : aes_sbox_fwd = 8'h72;
        31 : aes_sbox_fwd = 8'hc0;
        32 : aes_sbox_fwd = 8'hb7;
        33 : aes_sbox_fwd = 8'hfd;
        34 : aes_sbox_fwd = 8'h93;
        35 : aes_sbox_fwd = 8'h26;
        36 : aes_sbox_fwd = 8'h36;
        37 : aes_sbox_fwd = 8'h3f;
        38 : aes_sbox_fwd = 8'hf7;
        39 : aes_sbox_fwd = 8'hcc;
        40 : aes_sbox_fwd = 8'h34;
        41 : aes_sbox_fwd = 8'ha5;
        42 : aes_sbox_fwd = 8'he5;
        43 : aes_sbox_fwd = 8'hf1;
        44 : aes_sbox_fwd = 8'h71;
        45 : aes_sbox_fwd = 8'hd8;
        46 : aes_sbox_fwd = 8'h31;
        47 : aes_sbox_fwd = 8'h15;
        48 : aes_sbox_fwd = 8'h04;
        49 : aes_sbox_fwd = 8'hc7;
        50 : aes_sbox_fwd = 8'h23;
        51 : aes_sbox_fwd = 8'hc3;
        52 : aes_sbox_fwd = 8'h18;
        53 : aes_sbox_fwd = 8'h96;
        54 : aes_sbox_fwd = 8'h05;
        55 : aes_sbox_fwd = 8'h9a;
        56 : aes_sbox_fwd = 8'h07;
        57 : aes_sbox_fwd = 8'h12;
        58 : aes_sbox_fwd = 8'h80;
        59 : aes_sbox_fwd = 8'he2;
        60 : aes_sbox_fwd = 8'heb;
        61 : aes_sbox_fwd = 8'h27;
        62 : aes_sbox_fwd = 8'hb2;
        63 : aes_sbox_fwd = 8'h75;
        64 : aes_sbox_fwd = 8'h09;
        65 : aes_sbox_fwd = 8'h83;
        66 : aes_sbox_fwd = 8'h2c;
        67 : aes_sbox_fwd = 8'h1a;
        68 : aes_sbox_fwd = 8'h1b;
        69 : aes_sbox_fwd = 8'h6e;
        70 : aes_sbox_fwd = 8'h5a;
        71 : aes_sbox_fwd = 8'ha0;
        72 : aes_sbox_fwd = 8'h52;
        73 : aes_sbox_fwd = 8'h3b;
        74 : aes_sbox_fwd = 8'hd6;
        75 : aes_sbox_fwd = 8'hb3;
        76 : aes_sbox_fwd = 8'h29;
        77 : aes_sbox_fwd = 8'he3;
        78 : aes_sbox_fwd = 8'h2f;
        79 : aes_sbox_fwd = 8'h84;
        80 : aes_sbox_fwd = 8'h53;
        81 : aes_sbox_fwd = 8'hd1;
        82 : aes_sbox_fwd = 8'h00;
        83 : aes_sbox_fwd = 8'hed;
        84 : aes_sbox_fwd = 8'h20;
        85 : aes_sbox_fwd = 8'hfc;
        86 : aes_sbox_fwd = 8'hb1;
        87 : aes_sbox_fwd = 8'h5b;
        88 : aes_sbox_fwd = 8'h6a;
        89 : aes_sbox_fwd = 8'hcb;
        90 : aes_sbox_fwd = 8'hbe;
        91 : aes_sbox_fwd = 8'h39;
        92 : aes_sbox_fwd = 8'h4a;
        93 : aes_sbox_fwd = 8'h4c;
        94 : aes_sbox_fwd = 8'h58;
        95 : aes_sbox_fwd = 8'hcf;
        96 : aes_sbox_fwd = 8'hd0;
        97 : aes_sbox_fwd = 8'hef;
        98 : aes_sbox_fwd = 8'haa;
        99 : aes_sbox_fwd = 8'hfb;
        100: aes_sbox_fwd = 8'h43;
        101: aes_sbox_fwd = 8'h4d;
        102: aes_sbox_fwd = 8'h33;
        103: aes_sbox_fwd = 8'h85;
        104: aes_sbox_fwd = 8'h45;
        105: aes_sbox_fwd = 8'hf9;
        106: aes_sbox_fwd = 8'h02;
        107: aes_sbox_fwd = 8'h7f;
        108: aes_sbox_fwd = 8'h50;
        109: aes_sbox_fwd = 8'h3c;
        110: aes_sbox_fwd = 8'h9f;
        111: aes_sbox_fwd = 8'ha8;
        112: aes_sbox_fwd = 8'h51;
        113: aes_sbox_fwd = 8'ha3;
        114: aes_sbox_fwd = 8'h40;
        115: aes_sbox_fwd = 8'h8f;
        116: aes_sbox_fwd = 8'h92;
        117: aes_sbox_fwd = 8'h9d;
        118: aes_sbox_fwd = 8'h38;
        119: aes_sbox_fwd = 8'hf5;
        120: aes_sbox_fwd = 8'hbc;
        121: aes_sbox_fwd = 8'hb6;
        122: aes_sbox_fwd = 8'hda;
        123: aes_sbox_fwd = 8'h21;
        124: aes_sbox_fwd = 8'h10;
        125: aes_sbox_fwd = 8'hff;
        126: aes_sbox_fwd = 8'hf3;
        127: aes_sbox_fwd = 8'hd2;
        128: aes_sbox_fwd = 8'hcd;
        129: aes_sbox_fwd = 8'h0c;
        130: aes_sbox_fwd = 8'h13;
        131: aes_sbox_fwd = 8'hec;
        132: aes_sbox_fwd = 8'h5f;
        133: aes_sbox_fwd = 8'h97;
        134: aes_sbox_fwd = 8'h44;
        135: aes_sbox_fwd = 8'h17;
        136: aes_sbox_fwd = 8'hc4;
        137: aes_sbox_fwd = 8'ha7;
        138: aes_sbox_fwd = 8'h7e;
        139: aes_sbox_fwd = 8'h3d;
        140: aes_sbox_fwd = 8'h64;
        141: aes_sbox_fwd = 8'h5d;
        142: aes_sbox_fwd = 8'h19;
        143: aes_sbox_fwd = 8'h73;
        144: aes_sbox_fwd = 8'h60;
        145: aes_sbox_fwd = 8'h81;
        146: aes_sbox_fwd = 8'h4f;
        147: aes_sbox_fwd = 8'hdc;
        148: aes_sbox_fwd = 8'h22;
        149: aes_sbox_fwd = 8'h2a;
        150: aes_sbox_fwd = 8'h90;
        151: aes_sbox_fwd = 8'h88;
        152: aes_sbox_fwd = 8'h46;
        153: aes_sbox_fwd = 8'hee;
        154: aes_sbox_fwd = 8'hb8;
        155: aes_sbox_fwd = 8'h14;
        156: aes_sbox_fwd = 8'hde;
        157: aes_sbox_fwd = 8'h5e;
        158: aes_sbox_fwd = 8'h0b;
        159: aes_sbox_fwd = 8'hdb;
        160: aes_sbox_fwd = 8'he0;
        161: aes_sbox_fwd = 8'h32;
        162: aes_sbox_fwd = 8'h3a;
        163: aes_sbox_fwd = 8'h0a;
        164: aes_sbox_fwd = 8'h49;
        165: aes_sbox_fwd = 8'h06;
        166: aes_sbox_fwd = 8'h24;
        167: aes_sbox_fwd = 8'h5c;
        168: aes_sbox_fwd = 8'hc2;
        169: aes_sbox_fwd = 8'hd3;
        170: aes_sbox_fwd = 8'hac;
        171: aes_sbox_fwd = 8'h62;
        172: aes_sbox_fwd = 8'h91;
        173: aes_sbox_fwd = 8'h95;
        174: aes_sbox_fwd = 8'he4;
        175: aes_sbox_fwd = 8'h79;
        176: aes_sbox_fwd = 8'he7;
        177: aes_sbox_fwd = 8'hc8;
        178: aes_sbox_fwd = 8'h37;
        179: aes_sbox_fwd = 8'h6d;
        180: aes_sbox_fwd = 8'h8d;
        181: aes_sbox_fwd = 8'hd5;
        182: aes_sbox_fwd = 8'h4e;
        183: aes_sbox_fwd = 8'ha9;
        184: aes_sbox_fwd = 8'h6c;
        185: aes_sbox_fwd = 8'h56;
        186: aes_sbox_fwd = 8'hf4;
        187: aes_sbox_fwd = 8'hea;
        188: aes_sbox_fwd = 8'h65;
        189: aes_sbox_fwd = 8'h7a;
        190: aes_sbox_fwd = 8'hae;
        191: aes_sbox_fwd = 8'h08;
        192: aes_sbox_fwd = 8'hba;
        193: aes_sbox_fwd = 8'h78;
        194: aes_sbox_fwd = 8'h25;
        195: aes_sbox_fwd = 8'h2e;
        196: aes_sbox_fwd = 8'h1c;
        197: aes_sbox_fwd = 8'ha6;
        198: aes_sbox_fwd = 8'hb4;
        199: aes_sbox_fwd = 8'hc6;
        200: aes_sbox_fwd = 8'he8;
        201: aes_sbox_fwd = 8'hdd;
        202: aes_sbox_fwd = 8'h74;
        203: aes_sbox_fwd = 8'h1f;
        204: aes_sbox_fwd = 8'h4b;
        205: aes_sbox_fwd = 8'hbd;
        206: aes_sbox_fwd = 8'h8b;
        207: aes_sbox_fwd = 8'h8a;
        208: aes_sbox_fwd = 8'h70;
        209: aes_sbox_fwd = 8'h3e;
        210: aes_sbox_fwd = 8'hb5;
        211: aes_sbox_fwd = 8'h66;
        212: aes_sbox_fwd = 8'h48;
        213: aes_sbox_fwd = 8'h03;
        214: aes_sbox_fwd = 8'hf6;
        215: aes_sbox_fwd = 8'h0e;
        216: aes_sbox_fwd = 8'h61;
        217: aes_sbox_fwd = 8'h35;
        218: aes_sbox_fwd = 8'h57;
        219: aes_sbox_fwd = 8'hb9;
        220: aes_sbox_fwd = 8'h86;
        221: aes_sbox_fwd = 8'hc1;
        222: aes_sbox_fwd = 8'h1d;
        223: aes_sbox_fwd = 8'h9e;
        224: aes_sbox_fwd = 8'he1;
        225: aes_sbox_fwd = 8'hf8;
        226: aes_sbox_fwd = 8'h98;
        227: aes_sbox_fwd = 8'h11;
        228: aes_sbox_fwd = 8'h69;
        229: aes_sbox_fwd = 8'hd9;
        230: aes_sbox_fwd = 8'h8e;
        231: aes_sbox_fwd = 8'h94;
        232: aes_sbox_fwd = 8'h9b;
        233: aes_sbox_fwd = 8'h1e;
        234: aes_sbox_fwd = 8'h87;
        235: aes_sbox_fwd = 8'he9;
        236: aes_sbox_fwd = 8'hce;
        237: aes_sbox_fwd = 8'h55;
        238: aes_sbox_fwd = 8'h28;
        239: aes_sbox_fwd = 8'hdf;
        240: aes_sbox_fwd = 8'h8c;
        241: aes_sbox_fwd = 8'ha1;
        242: aes_sbox_fwd = 8'h89;
        243: aes_sbox_fwd = 8'h0d;
        244: aes_sbox_fwd = 8'hbf;
        245: aes_sbox_fwd = 8'he6;
        246: aes_sbox_fwd = 8'h42;
        247: aes_sbox_fwd = 8'h68;
        248: aes_sbox_fwd = 8'h41;
        249: aes_sbox_fwd = 8'h99;
        250: aes_sbox_fwd = 8'h2d;
        251: aes_sbox_fwd = 8'h0f;
        252: aes_sbox_fwd = 8'hb0;
        253: aes_sbox_fwd = 8'h54;
        254: aes_sbox_fwd = 8'hbb;
        255: aes_sbox_fwd = 8'h16;
    endcase
endfunction

function [7:0] aes_sbox_inv;
    input [7:0] in;
    case(in)
        0  : aes_sbox_inv = 8'h52;
        1  : aes_sbox_inv = 8'h09;
        2  : aes_sbox_inv = 8'h6a;
        3  : aes_sbox_inv = 8'hd5;
        4  : aes_sbox_inv = 8'h30;
        5  : aes_sbox_inv = 8'h36;
        6  : aes_sbox_inv = 8'ha5;
        7  : aes_sbox_inv = 8'h38;
        8  : aes_sbox_inv = 8'hbf;
        9  : aes_sbox_inv = 8'h40;
        10 : aes_sbox_inv = 8'ha3;
        11 : aes_sbox_inv = 8'h9e;
        12 : aes_sbox_inv = 8'h81;
        13 : aes_sbox_inv = 8'hf3;
        14 : aes_sbox_inv = 8'hd7;
        15 : aes_sbox_inv = 8'hfb;
        16 : aes_sbox_inv = 8'h7c;
        17 : aes_sbox_inv = 8'he3;
        18 : aes_sbox_inv = 8'h39;
        19 : aes_sbox_inv = 8'h82;
        20 : aes_sbox_inv = 8'h9b;
        21 : aes_sbox_inv = 8'h2f;
        22 : aes_sbox_inv = 8'hff;
        23 : aes_sbox_inv = 8'h87;
        24 : aes_sbox_inv = 8'h34;
        25 : aes_sbox_inv = 8'h8e;
        26 : aes_sbox_inv = 8'h43;
        27 : aes_sbox_inv = 8'h44;
        28 : aes_sbox_inv = 8'hc4;
        29 : aes_sbox_inv = 8'hde;
        30 : aes_sbox_inv = 8'he9;
        31 : aes_sbox_inv = 8'hcb;
        32 : aes_sbox_inv = 8'h54;
        33 : aes_sbox_inv = 8'h7b;
        34 : aes_sbox_inv = 8'h94;
        35 : aes_sbox_inv = 8'h32;
        36 : aes_sbox_inv = 8'ha6;
        37 : aes_sbox_inv = 8'hc2;
        38 : aes_sbox_inv = 8'h23;
        39 : aes_sbox_inv = 8'h3d;
        40 : aes_sbox_inv = 8'hee;
        41 : aes_sbox_inv = 8'h4c;
        42 : aes_sbox_inv = 8'h95;
        43 : aes_sbox_inv = 8'h0b;
        44 : aes_sbox_inv = 8'h42;
        45 : aes_sbox_inv = 8'hfa;
        46 : aes_sbox_inv = 8'hc3;
        47 : aes_sbox_inv = 8'h4e;
        48 : aes_sbox_inv = 8'h08;
        49 : aes_sbox_inv = 8'h2e;
        50 : aes_sbox_inv = 8'ha1;
        51 : aes_sbox_inv = 8'h66;
        52 : aes_sbox_inv = 8'h28;
        53 : aes_sbox_inv = 8'hd9;
        54 : aes_sbox_inv = 8'h24;
        55 : aes_sbox_inv = 8'hb2;
        56 : aes_sbox_inv = 8'h76;
        57 : aes_sbox_inv = 8'h5b;
        58 : aes_sbox_inv = 8'ha2;
        59 : aes_sbox_inv = 8'h49;
        60 : aes_sbox_inv = 8'h6d;
        61 : aes_sbox_inv = 8'h8b;
        62 : aes_sbox_inv = 8'hd1;
        63 : aes_sbox_inv = 8'h25;
        64 : aes_sbox_inv = 8'h72;
        65 : aes_sbox_inv = 8'hf8;
        66 : aes_sbox_inv = 8'hf6;
        67 : aes_sbox_inv = 8'h64;
        68 : aes_sbox_inv = 8'h86;
        69 : aes_sbox_inv = 8'h68;
        70 : aes_sbox_inv = 8'h98;
        71 : aes_sbox_inv = 8'h16;
        72 : aes_sbox_inv = 8'hd4;
        73 : aes_sbox_inv = 8'ha4;
        74 : aes_sbox_inv = 8'h5c;
        75 : aes_sbox_inv = 8'hcc;
        76 : aes_sbox_inv = 8'h5d;
        77 : aes_sbox_inv = 8'h65;
        78 : aes_sbox_inv = 8'hb6;
        79 : aes_sbox_inv = 8'h92;
        80 : aes_sbox_inv = 8'h6c;
        81 : aes_sbox_inv = 8'h70;
        82 : aes_sbox_inv = 8'h48;
        83 : aes_sbox_inv = 8'h50;
        84 : aes_sbox_inv = 8'hfd;
        85 : aes_sbox_inv = 8'hed;
        86 : aes_sbox_inv = 8'hb9;
        87 : aes_sbox_inv = 8'hda;
        88 : aes_sbox_inv = 8'h5e;
        89 : aes_sbox_inv = 8'h15;
        90 : aes_sbox_inv = 8'h46;
        91 : aes_sbox_inv = 8'h57;
        92 : aes_sbox_inv = 8'ha7;
        93 : aes_sbox_inv = 8'h8d;
        94 : aes_sbox_inv = 8'h9d;
        95 : aes_sbox_inv = 8'h84;
        96 : aes_sbox_inv = 8'h90;
        97 : aes_sbox_inv = 8'hd8;
        98 : aes_sbox_inv = 8'hab;
        99 : aes_sbox_inv = 8'h00;
        100: aes_sbox_inv = 8'h8c;
        101: aes_sbox_inv = 8'hbc;
        102: aes_sbox_inv = 8'hd3;
        103: aes_sbox_inv = 8'h0a;
        104: aes_sbox_inv = 8'hf7;
        105: aes_sbox_inv = 8'he4;
        106: aes_sbox_inv = 8'h58;
        107: aes_sbox_inv = 8'h05;
        108: aes_sbox_inv = 8'hb8;
        109: aes_sbox_inv = 8'hb3;
        110: aes_sbox_inv = 8'h45;
        111: aes_sbox_inv = 8'h06;
        112: aes_sbox_inv = 8'hd0;
        113: aes_sbox_inv = 8'h2c;
        114: aes_sbox_inv = 8'h1e;
        115: aes_sbox_inv = 8'h8f;
        116: aes_sbox_inv = 8'hca;
        117: aes_sbox_inv = 8'h3f;
        118: aes_sbox_inv = 8'h0f;
        119: aes_sbox_inv = 8'h02;
        120: aes_sbox_inv = 8'hc1;
        121: aes_sbox_inv = 8'haf;
        122: aes_sbox_inv = 8'hbd;
        123: aes_sbox_inv = 8'h03;
        124: aes_sbox_inv = 8'h01;
        125: aes_sbox_inv = 8'h13;
        126: aes_sbox_inv = 8'h8a;
        127: aes_sbox_inv = 8'h6b;
        128: aes_sbox_inv = 8'h3a;
        129: aes_sbox_inv = 8'h91;
        130: aes_sbox_inv = 8'h11;
        131: aes_sbox_inv = 8'h41;
        132: aes_sbox_inv = 8'h4f;
        133: aes_sbox_inv = 8'h67;
        134: aes_sbox_inv = 8'hdc;
        135: aes_sbox_inv = 8'hea;
        136: aes_sbox_inv = 8'h97;
        137: aes_sbox_inv = 8'hf2;
        138: aes_sbox_inv = 8'hcf;
        139: aes_sbox_inv = 8'hce;
        140: aes_sbox_inv = 8'hf0;
        141: aes_sbox_inv = 8'hb4;
        142: aes_sbox_inv = 8'he6;
        143: aes_sbox_inv = 8'h73;
        144: aes_sbox_inv = 8'h96;
        145: aes_sbox_inv = 8'hac;
        146: aes_sbox_inv = 8'h74;
        147: aes_sbox_inv = 8'h22;
        148: aes_sbox_inv = 8'he7;
        149: aes_sbox_inv = 8'had;
        150: aes_sbox_inv = 8'h35;
        151: aes_sbox_inv = 8'h85;
        152: aes_sbox_inv = 8'he2;
        153: aes_sbox_inv = 8'hf9;
        154: aes_sbox_inv = 8'h37;
        155: aes_sbox_inv = 8'he8;
        156: aes_sbox_inv = 8'h1c;
        157: aes_sbox_inv = 8'h75;
        158: aes_sbox_inv = 8'hdf;
        159: aes_sbox_inv = 8'h6e;
        160: aes_sbox_inv = 8'h47;
        161: aes_sbox_inv = 8'hf1;
        162: aes_sbox_inv = 8'h1a;
        163: aes_sbox_inv = 8'h71;
        164: aes_sbox_inv = 8'h1d;
        165: aes_sbox_inv = 8'h29;
        166: aes_sbox_inv = 8'hc5;
        167: aes_sbox_inv = 8'h89;
        168: aes_sbox_inv = 8'h6f;
        169: aes_sbox_inv = 8'hb7;
        170: aes_sbox_inv = 8'h62;
        171: aes_sbox_inv = 8'h0e;
        172: aes_sbox_inv = 8'haa;
        173: aes_sbox_inv = 8'h18;
        174: aes_sbox_inv = 8'hbe;
        175: aes_sbox_inv = 8'h1b;
        176: aes_sbox_inv = 8'hfc;
        177: aes_sbox_inv = 8'h56;
        178: aes_sbox_inv = 8'h3e;
        179: aes_sbox_inv = 8'h4b;
        180: aes_sbox_inv = 8'hc6;
        181: aes_sbox_inv = 8'hd2;
        182: aes_sbox_inv = 8'h79;
        183: aes_sbox_inv = 8'h20;
        184: aes_sbox_inv = 8'h9a;
        185: aes_sbox_inv = 8'hdb;
        186: aes_sbox_inv = 8'hc0;
        187: aes_sbox_inv = 8'hfe;
        188: aes_sbox_inv = 8'h78;
        189: aes_sbox_inv = 8'hcd;
        190: aes_sbox_inv = 8'h5a;
        191: aes_sbox_inv = 8'hf4;
        192: aes_sbox_inv = 8'h1f;
        193: aes_sbox_inv = 8'hdd;
        194: aes_sbox_inv = 8'ha8;
        195: aes_sbox_inv = 8'h33;
        196: aes_sbox_inv = 8'h88;
        197: aes_sbox_inv = 8'h07;
        198: aes_sbox_inv = 8'hc7;
        199: aes_sbox_inv = 8'h31;
        200: aes_sbox_inv = 8'hb1;
        201: aes_sbox_inv = 8'h12;
        202: aes_sbox_inv = 8'h10;
        203: aes_sbox_inv = 8'h59;
        204: aes_sbox_inv = 8'h27;
        205: aes_sbox_inv = 8'h80;
        206: aes_sbox_inv = 8'hec;
        207: aes_sbox_inv = 8'h5f;
        208: aes_sbox_inv = 8'h60;
        209: aes_sbox_inv = 8'h51;
        210: aes_sbox_inv = 8'h7f;
        211: aes_sbox_inv = 8'ha9;
        212: aes_sbox_inv = 8'h19;
        213: aes_sbox_inv = 8'hb5;
        214: aes_sbox_inv = 8'h4a;
        215: aes_sbox_inv = 8'h0d;
        216: aes_sbox_inv = 8'h2d;
        217: aes_sbox_inv = 8'he5;
        218: aes_sbox_inv = 8'h7a;
        219: aes_sbox_inv = 8'h9f;
        220: aes_sbox_inv = 8'h93;
        221: aes_sbox_inv = 8'hc9;
        222: aes_sbox_inv = 8'h9c;
        223: aes_sbox_inv = 8'hef;
        224: aes_sbox_inv = 8'ha0;
        225: aes_sbox_inv = 8'he0;
        226: aes_sbox_inv = 8'h3b;
        227: aes_sbox_inv = 8'h4d;
        228: aes_sbox_inv = 8'hae;
        229: aes_sbox_inv = 8'h2a;
        230: aes_sbox_inv = 8'hf5;
        231: aes_sbox_inv = 8'hb0;
        232: aes_sbox_inv = 8'hc8;
        233: aes_sbox_inv = 8'heb;
        234: aes_sbox_inv = 8'hbb;
        235: aes_sbox_inv = 8'h3c;
        236: aes_sbox_inv = 8'h83;
        237: aes_sbox_inv = 8'h53;
        238: aes_sbox_inv = 8'h99;
        239: aes_sbox_inv = 8'h61;
        240: aes_sbox_inv = 8'h17;
        241: aes_sbox_inv = 8'h2b;
        242: aes_sbox_inv = 8'h04;
        243: aes_sbox_inv = 8'h7e;
        244: aes_sbox_inv = 8'hba;
        245: aes_sbox_inv = 8'h77;
        246: aes_sbox_inv = 8'hd6;
        247: aes_sbox_inv = 8'h26;
        248: aes_sbox_inv = 8'he1;
        249: aes_sbox_inv = 8'h69;
        250: aes_sbox_inv = 8'h14;
        251: aes_sbox_inv = 8'h63;
        252: aes_sbox_inv = 8'h55;
        253: aes_sbox_inv = 8'h21;
        254: aes_sbox_inv = 8'h0c;
        255: aes_sbox_inv = 8'h7d;
    endcase
endfunction


//
// Multiply by 2 in GF(2^8) modulo 8'h1b
function [7:0] xt2;
    input [7:0] a;
    xt2 = (a << 1) ^ (a[7] ? 8'h1b : 8'b0) ;
endfunction

//
// Paired down multiply by X in GF(2^8)
function [7:0] xtN;
    input[7:0] a;
    input[3:0] b;
    xtN = (b[0] ?             a   : 0) ^
          (b[1] ? xt2(        a)  : 0) ^
          (b[2] ? xt2(xt2(    a)) : 0) ^
          (b[3] ? xt2(xt2(xt2(a))): 0) ;
endfunction

//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_byte_enc;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_byte_enc = xtN(b0,4'd2) ^ xtN(b1,4'd3) ^ b2 ^ b3;
endfunction

//
// Performs the mix column transformation on a single word.
function [7:0] mixcolumn_byte_dec;
    input [7:0] b0, b1, b2, b3;
    mixcolumn_byte_dec = xtN(b0,4'he) ^ xtN(b1,4'hb) ^ xtN(b2,4'hd) ^ xtN(b3,4'h9);
endfunction


function [31:0] mixcolumn_word_enc;
    input[31:0] word    ;
    reg  [ 7:0] mix_3   ;
    reg  [ 7:0] mix_2   ;
    reg  [ 7:0] mix_1   ;
    reg  [ 7:0] mix_0   ;
    mix_3   = word[31:24];
    mix_2   = word[23:16];
    mix_1   = word[15: 8];
    mix_0   = word[ 7: 0];
    mixcolumn_word_enc[31:24] = mixcolumn_byte_enc(mix_3, mix_0, mix_1, mix_2);
    mixcolumn_word_enc[23:16] = mixcolumn_byte_enc(mix_2, mix_3, mix_0, mix_1);
    mixcolumn_word_enc[15: 8] = mixcolumn_byte_enc(mix_1, mix_2, mix_0, mix_3);
    mixcolumn_word_enc[ 7: 0] = mixcolumn_byte_enc(mix_0, mix_1, mix_2, mix_3);
endfunction


function [31:0] mixcolumn_word_dec;
    input[31:0] word    ;
    reg  [ 7:0] mix_3   ;
    reg  [ 7:0] mix_2   ;
    reg  [ 7:0] mix_1   ;
    reg  [ 7:0] mix_0   ;
    mix_3   = word[31:24];
    mix_2   = word[23:16];
    mix_1   = word[15: 8];
    mix_0   = word[ 7: 0];
    mixcolumn_word_dec[31:24] = mixcolumn_byte_dec(mix_3, mix_0, mix_1, mix_2);
    mixcolumn_word_dec[23:16] = mixcolumn_byte_dec(mix_2, mix_3, mix_0, mix_1);
    mixcolumn_word_dec[15: 8] = mixcolumn_byte_dec(mix_1, mix_2, mix_0, mix_3);
    mixcolumn_word_dec[ 7: 0] = mixcolumn_byte_dec(mix_0, mix_1, mix_2, mix_3);
endfunction

