/* -*- P4_16 -*- */
/*
 * Define the headers the program will recognize
 */
#include <core.p4>
#include <v1model.p4>
//const type
const bit<16>  TYPE_ADDER   = 1234;
const bit<16>  TYPE_IPV4    = 0x0800;
const bit<16>  TYPE_ARP     = 0x0806;
const bit<8>   TYPE_TCP     = 0x06;
const bit<8>   TYPE_UDP     = 0x11;
/*
 * This is a custom protocol header for the calculator. We'll use
 * etherType 0x1234 for it (see parser)
 */
const bit<8>  ADDER_A             = 0x41;
const bit<8>  ADDER_D             = 0x44;
const bit<8>  ADDER_VERSION_MAJOR = 0x00;
const bit<8>  ADDER_VERSION_MINOR = 0x01;

// the address of hosts
const bit<48> HOST_1_ADDR         = 0x080000000101;
const bit<48> HOST_2_ADDR         = 0x080000000102;
const bit<48> DST_MAC             = 0x080000000103;
const bit<32> HOST_1_IP           = 0x0a000101;
const bit<32> HOST_2_IP           = 0x0a000102;
const bit<32> DST_IP              = 0x0a000103;
const bit<9>  HOST_1_PORT         = 1;
const bit<9>  HOST_2_PORT         = 2;
const bit<9>  DST_PORT            = 3;

// buffer size
const bit<32> BUFFER_SIZE         = 256;

/*
        1               2               3               4
Ethernet header
+---------------+---------------+---------------+---------------+
|                         dst_addr<48>                          |
+---------------+---------------+---------------+---------------+
|                         src_addr<48>                          |
+---------------+---------------+---------------+---------------+
|           ether_type          |                               |
+---------------+---------------+---------------+---------------+   

IP header
+---------------+---------------+---------------+---------------+                               
|   version     |       ihl     |    diffserv   |   totalLen    |
+---------------+---------------+---------------+---------------+
|        identification         | flags<3>|      fragOffset<13> |
+---------------+---------------+---------------+---------------+
|       ttl     |   protocol    |           hdrChecksum         |
+---------------+---------------+---------------+---------------+
|                            srcAddr                            |
+---------------+---------------+---------------+---------------+
|                            dstAddr                            |
+---------------+---------------+---------------+---------------+

TCP header
+---------------+---------------+---------------+---------------+   
|            Src_port           |            Dst_port           |
+---------------+---------------+---------------+---------------+
|                            seq_num                            |
+---------------+---------------+---------------+---------------+
|                            ack_num                            |
+---------------+---------------+---------------+---------------+
|dt_of<4>|re<3>|   ctl_fl<9>    |          window_size<16>      |
+---------------+---------------+---------------+---------------+
|            Checksum           |           ugrent_num          |
+---------------+---------------+---------------+---------------+
|                            options                            |   
+---------------+---------------+---------------+---------------+

Adder header
+---------------+---------------+---------------+---------------+
|      'A'      |      'D'      | VERSION_MAJOR | VERSION_MINOR |
+---------------+---------------+---------------+---------------+
|    SEQ_NUM    |   IS_RESULT   |                               |
+---------------------------------------------------------------+
|                              NUM                              |
+---------------------------------------------------------------+
*/
//TCP+IP+ETHENET header
/*
 * Standard Ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}
header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seq_num;
    bit<32> ack_num;
    bit<4>  data_offset;
    bit<3>  reserved;
    bit<9>  ctl_flag;
    bit<16> window_size;
    bit<16> checksum;
    bit<16> urgent_num;
}
//tcp option type
//kind = 0 end of option list
header Tcp_option_end_h { 
    bit<8> kind;
}
//kind = 1 no operation
header Tcp_option_nop_h {  
    bit<8> kind;
}
//kind = 2 max segment size
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<8>  length;
    bit<16> max_segment_size;
}
//kind = 3 shift count
header Tcp_option_s_h {
    bit<8>  kind;
    bit<8>  length;
    bit<8>  shift_count;
}
//kind = 4  sack permitted
header Tcp_option_sp_h {
    bit<8> kind;
    bit<8> length;
}
//kind = 5 sack
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}
//kind = 8 timestamp
header Tcp_option_ts_h {
    bit<8> kind;
    bit<8> length;
    bit<32> ts_val;
    bit<32> ts_ecr;
}
header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sp_h   sp;
    Tcp_option_sack_h sack;
    Tcp_option_ts_h   ts;
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<160> padding;
}

header adder_t {
    bit<8>  a;
    bit<8>  d;
    bit<8>  ver_maj;
    bit<8>  ver_min;
    bit<8>  seq_num;
    bit<8>  is_result;
    bit<32> num;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    //udp_t        udp;
    tcp_t        tcp;
    Tcp_option_stack tcp_options_vec;
    Tcp_option_padding_h tcp_options_padding;
    adder_t      adder;
}
error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}
/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    bit<16> tcp_length; // tcp header length using at checksum calculation
    bit<16> tot_length; // total length with adder header 
    bit<32> h2_tcp_seqnum;
    bit<32> h2_tcp_acknum;
    bit<16> h2_tcp_port;
    bit<1>  ack_valid;
    bit<8>  tcp_nop;
    bit<8>  tcp_ts;
    bit<8>  tcp_ts_len;
    bit<32> tcp_ts_ts_val;
    bit<32> tcp_ts_ts_ecr;
}
parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        transition next_option;
        // transition consume_remaining_tcp_hdr_and_accept;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
        // precondition: tcp_hdr_bytes_left >= 1
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;  // end
            1: parse_tcp_option_nop;  //no operation
            2: parse_tcp_option_ss;   // max segment size
            3: parse_tcp_option_s;    // window scale(shift)
            4: parse_tcp_option_sp;   //sack permitted
            5: parse_tcp_option_sack; //sack
            8: parse_tcp_option_ts;   //timestamp
        }
    }
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        // TBD: This code is an example demonstrating why it would be
        // useful to have sizeof(vec.next.end) instead of having to
        // put in a hard-coded length for each TCP option.
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state parse_tcp_option_nop { 
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 3, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 3;
        b.extract(vec.next.s);
        transition next_option;
    }
    state parse_tcp_option_sp {
        verify(tcp_hdr_bytes_left >= 2, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 2;
        b.extract(vec.next.sp);
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_ts {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.ts);
        transition next_option;
    }
    state consume_remaining_tcp_hdr_and_accept {
        // A more picky sub-parser implementation would verify that
        // all of the remaining bytes are 0, as specified in RFC 793,
        // setting an error and rejecting if not.  This one skips past
        // the rest of the TCP header without checking this.

        // tcp_hdr_bytes_left might be as large as 40, so multiplying
        // it by 8 it may be up to 320, which requires 9 bits to avoid
        // losing any information.
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    
    state start {
        transition parse_ethernet;
    }
    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4     : parse_ipv4;
            default       : accept;
        }
    }
    state parse_ipv4{
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            //TYPE_UDP  : parse_udp;
            TYPE_TCP  : parse_tcp;
            default   : accept;
        }
    }
    // state parse_udp{
    //     packet.extract(hdr.udp);
    //     transition select(hdr.udp.dstPort) {
    //         TYPE_ADDER : check_adder;
    //         default    : accept;
    //     }
    // }
    state parse_tcp{
        packet.extract(hdr.tcp);
        meta.tcp_length = (bit<16>)hdr.tcp.data_offset * 4;
        meta.tot_length = meta.tcp_length + 10;
        Tcp_option_parser.apply(packet, hdr.tcp.data_offset,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);
        transition check_adder;
    }
    state check_adder {
        transition select(packet.lookahead<adder_t>().a,
        packet.lookahead<adder_t>().d,
        packet.lookahead<adder_t>().ver_maj,
        packet.lookahead<adder_t>().ver_min) {
            (ADDER_A, ADDER_D, ADDER_VERSION_MAJOR, ADDER_VERSION_MINOR) : parse_adder;
            default                                                      : accept;
        }
    }

    state parse_adder {
        packet.extract(hdr.adder);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<32>>(BUFFER_SIZE) num_buffer;
    register<bit<1>> (BUFFER_SIZE) num_buffer_valid;
    register<bit<9>> (BUFFER_SIZE) num_buffer_author;
    register<bit<16>>(BUFFER_SIZE) num_buffer_tcp_port;         //store tcp port of every host
    register<bit<32>>(BUFFER_SIZE) num_buffer_tcp_seqnum;       //store tcp seqnum of the first packet
    register<bit<32>>(BUFFER_SIZE) num_buffer_tcp_acknum;       //store tcp acknum of the first packet
    register<bit<32>>(BUFFER_SIZE) num_buffer_tcp_ts_val;       //store tcp ts_val of the first packet(mainly host 2)
    register<bit<32>>(BUFFER_SIZE) num_buffer_tcp_ts_ecr;       //store tcp ts_ecr of the first packet(mainly host 2


    register<bit<32>>(BUFFER_SIZE) packet_buffer_tcp_seqnum;      //store tcp seqnum of the second packet for ack
    register<bit<32>>(BUFFER_SIZE) packet_buffer_tcp_acknum;      //store tcp acknum of the second packet for ack
    register<bit<32>>(BUFFER_SIZE) packet_buffer_tcp_ts_val;
    register<bit<32>>(BUFFER_SIZE) packet_buffer_tcp_ts_ecr;
    register<bit<1>> (BUFFER_SIZE) packet_buffer_packet_valid;
    action save_result(bit<32> result, bit<8> seq_num) {
        // save the result in header
        hdr.adder.num = result;
        hdr.adder.seq_num = seq_num;
    }
    action save_num(bit<32> index, bit<32> num, bit<9> author) {
        num_buffer.write(index, num);
        num_buffer_valid.write(index, 1);
        num_buffer_author.write(index, author);
    }
    action delete_num(bit<32> index) {
        num_buffer.write(index, 0);
        num_buffer_valid.write(index, 0);
        num_buffer_author.write(index, 0);
    }
    action save_tcp_info(bit<32> index, bit<32> seq_num, bit<32> ack_num, bit<32> ts_val, bit<32> ts_ecr) {
        num_buffer_tcp_seqnum.write(index, seq_num);
        num_buffer_tcp_acknum.write(index, ack_num);
        num_buffer_tcp_ts_val.write(index, ts_val);
        num_buffer_tcp_ts_ecr.write(index, ts_ecr);
    }
    action save_tcp_option(){
        meta.tcp_nop = 0x01;
        meta.tcp_ts = 0x08;
        meta.tcp_ts_len = 0x0a;
        meta.tcp_ts_ts_val = hdr.tcp_options_vec[2].ts.ts_val;
        meta.tcp_ts_ts_ecr = hdr.tcp_options_vec[2].ts.ts_ecr;
    }
    action modify_tcp(bit<32> seq_num, bit<32> ack_num) {
        bit<32> tcp_port_index;
        bit<32> base = 0;
        bit<16> tcp_port;
        num_buffer_tcp_port.read(tcp_port, 1);
        hdr.tcp.srcPort = tcp_port;
        hdr.tcp.seq_num = seq_num;
        hdr.tcp.ack_num = ack_num;
        hdr.ipv4.srcAddr = HOST_1_IP;
    }
    action drop() {
        // drop the packet
        mark_to_drop(standard_metadata);
    }

    action send_result(bit<9> port) {
        // forward the packet to the destination
        hdr.ethernet.dstAddr = DST_MAC;
        standard_metadata.egress_spec = port;
    }
    action multicast() {
        standard_metadata.mcast_grp = 1;
    }
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
    }
    table ipv4_lookup{
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
           ipv4_forward;
           drop;
           multicast;
        }
        size = 1024;
        default_action = multicast;
    }
    apply {
        if(hdr.tcp.isValid() && ((bit<8>)hdr.tcp.ctl_flag&0x10)==0x10 && (hdr.tcp.ctl_flag&0x02)!=0x02){
            bit<32> packet_index;
            bit<32> base = 0;
            bit<1>  packet_valid;
            hash(packet_index, HashAlgorithm.crc32, base, {hdr.tcp.ack_num-10, hdr.tcp.seq_num}, BUFFER_SIZE - 1);
            packet_buffer_packet_valid.read(packet_valid, packet_index);
            if(packet_valid==1){
                meta.ack_valid=1;
                meta.tcp_nop=0x01;
                meta.tcp_ts=0x08;
                meta.tcp_ts_len=0x0a;
                // meta.tcp_ts_ts_val=hdr.tcp_options_vec[2].ts.ts_val;
                packet_buffer_tcp_seqnum.read(meta.h2_tcp_seqnum, packet_index);
                packet_buffer_tcp_acknum.read(meta.h2_tcp_acknum, packet_index);
                packet_buffer_tcp_ts_val.read(meta.tcp_ts_ts_ecr, packet_index);
                packet_buffer_tcp_ts_ecr.read(meta.tcp_ts_ts_val, packet_index);
                num_buffer_tcp_port.read(meta.h2_tcp_port ,2);
                multicast();
            }
        }
        if (hdr.adder.isValid()) {
            // read the number from the register
            bit<32> num;
            bit<1>  valid;
            bit<9>  author;
            bit<32> index;
            bit<32> base = 0;
            bit<9>  srcPort = standard_metadata.ingress_port;
            hash(index, HashAlgorithm.crc32, base, {hdr.adder.seq_num}, BUFFER_SIZE - 1);
            num_buffer.read(num, index);
            num_buffer_valid.read(valid, index);
            num_buffer_author.read(author, index);

            //store the tcp port of every host
            num_buffer_tcp_port.write((bit<32>)standard_metadata.ingress_port, hdr.tcp.srcPort);
            // based on valid, determine what to do:
            // 1. if valid == 0, then the register is empty, so we need to
            //    buffer the number and wait for the next packet
            // 2. if valid == 1, then the register is full, so we can
            //    proceed with the calculation
            // the register is empty
            if (valid == 0) { 
                // save the number in the register
                save_num(index, hdr.adder.num, srcPort);
                save_tcp_info(index, hdr.tcp.seq_num, hdr.tcp.ack_num,hdr.tcp_options_vec[2].ts.ts_val, hdr.tcp_options_vec[2].ts.ts_ecr);
                drop();
            }
            // the register is occupied by another host
            else if (valid == 1 && srcPort != author) { 
                // calculate the result
                bit<32> result = num + hdr.adder.num;
                bit<32> host1_tcp_seqnum;
                bit<32> host1_tcp_acknum;
                bit<32> host1_tcp_ts_val;
                bit<32> host1_tcp_ts_ecr;
                bit<32> packet_index;
                // save the result in header and clear the register
                save_result(result, hdr.adder.seq_num);
                save_tcp_option();
                if(author==1){ //save host 2's tcp info
                    num_buffer_tcp_seqnum.read(host1_tcp_seqnum, index);
                    num_buffer_tcp_acknum.read(host1_tcp_acknum, index);
                    num_buffer_tcp_ts_val.read(host1_tcp_ts_val, index);
                    num_buffer_tcp_ts_ecr.read(host1_tcp_ts_ecr, index);
                    hash(packet_index, HashAlgorithm.crc32, base, {host1_tcp_seqnum, host1_tcp_acknum}, BUFFER_SIZE - 1);
                    packet_buffer_tcp_seqnum.write(packet_index, hdr.tcp.seq_num);  //store the seqnum of the second packet
                    packet_buffer_tcp_acknum.write(packet_index, hdr.tcp.ack_num);  //store the acknum of the second packet
                    packet_buffer_tcp_ts_val.write(packet_index, hdr.tcp_options_vec[2].ts.ts_val); //store the ts_val of the second packet
                    packet_buffer_tcp_ts_val.write(packet_index, hdr.tcp_options_vec[2].ts.ts_ecr); //store the ts_ecr of the second packet
                    packet_buffer_packet_valid.write(packet_index, 1);
                }
                else{
                    hash(packet_index, HashAlgorithm.crc32, base, {hdr.tcp.seq_num, hdr.tcp.ack_num}, BUFFER_SIZE - 1);
                    bit<32> host2_tcp_seqnum;
                    bit<32> host2_tcp_acknum;
                    bit<32> host2_tcp_ts_val;
                    bit<32> host2_tcp_ts_ecr;
                    host1_tcp_seqnum=hdr.tcp.seq_num;
                    host1_tcp_acknum=hdr.tcp.ack_num;
                    num_buffer_tcp_seqnum.read(host2_tcp_seqnum, index);
                    num_buffer_tcp_acknum.read(host2_tcp_acknum, index);
                    num_buffer_tcp_ts_val.read(host2_tcp_ts_val, index);
                    num_buffer_tcp_ts_ecr.read(host2_tcp_ts_ecr, index);
                    packet_buffer_tcp_seqnum.write(packet_index, host2_tcp_seqnum);  //store the seqnum of the second packet
                    packet_buffer_tcp_acknum.write(packet_index, host2_tcp_acknum);  //store the acknum of the second packet
                    packet_buffer_tcp_ts_val.write(packet_index, host2_tcp_ts_val); //store the ts_val of the second packet
                    packet_buffer_tcp_ts_val.write(packet_index, host2_tcp_ts_ecr); //store the ts_ecr of the second packet
                    packet_buffer_packet_valid.write(packet_index, 1);
                }
                delete_num(index);
                modify_tcp(host1_tcp_seqnum, host1_tcp_acknum);
                send_result(DST_PORT);
            }
            else { // the register is occupied by the same host
                // drop the packet
                drop();
            }
        } 
        else {
            ipv4_lookup.apply();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if (standard_metadata.egress_port == standard_metadata.ingress_port) drop();

        if(standard_metadata.mcast_grp==1 && standard_metadata.egress_port==2&&hdr.tcp.isValid()){
            hdr.tcp.ack_num = meta.h2_tcp_seqnum+10;
            hdr.tcp.seq_num = meta.h2_tcp_acknum;
            hdr.tcp.dstPort = meta.h2_tcp_port;
            meta.tcp_ts_ts_val = meta.tcp_ts_ts_val+20;
            hdr.tcp_options_vec[2].ts.ts_val = meta.tcp_ts_ts_val;
            hdr.tcp_options_vec[2].ts.ts_ecr = meta.tcp_ts_ts_ecr;
            hdr.ipv4.dstAddr = HOST_2_IP;
            hdr.ethernet.dstAddr = HOST_2_ADDR;

        }
        else if(standard_metadata.egress_port==1 && meta.ack_valid==1){
            meta.tcp_ts_ts_ecr = hdr.tcp_options_vec[2].ts.ts_ecr;
            meta.tcp_ts_ts_val = hdr.tcp_options_vec[2].ts.ts_val;
        }
    }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),  // condition: true if IPv4 header is valid
            {
                hdr.ipv4.version, 
                hdr.ipv4.ihl, 
                hdr.ipv4.diffserv, 
                hdr.ipv4.totalLen,
                hdr.ipv4.identification, 
                hdr.ipv4.flags, 
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, 
                hdr.ipv4.protocol, 
                hdr.ipv4.srcAddr, 
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,  // field to update with computed checksum
            HashAlgorithm.csum16  // checksum algorithm
        );
        update_checksum_with_payload(hdr.adder.isValid(),{
            //tcp checksum is usually calculated with the following fields
            //pseudo header+tcp header+tcp payload
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            meta.tot_length,   // 16 bit of tcp length + payload length in bytes
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seq_num,
            hdr.tcp.ack_num,
            hdr.tcp.data_offset,
            hdr.tcp.reserved,
            hdr.tcp.ctl_flag,
            hdr.tcp.window_size,
            hdr.tcp.urgent_num,
            meta.tcp_nop,
            meta.tcp_nop,
            meta.tcp_ts,
            meta.tcp_ts_len,
            meta.tcp_ts_ts_val,
            meta.tcp_ts_ts_ecr,
            hdr.tcp_options_padding.padding,
            hdr.adder.a,
            hdr.adder.d,
            hdr.adder.ver_maj,
            hdr.adder.ver_min,
            hdr.adder.seq_num,
            hdr.adder.is_result,
            hdr.adder.num
        }, hdr.tcp.checksum, HashAlgorithm.csum16);
        update_checksum(meta.ack_valid==1, {
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr,
            8w0,               //zero padding with protocol
            hdr.ipv4.protocol,
            meta.tcp_length,   // 16 bit of tcp length + payload length in bytes
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.seq_num,
            hdr.tcp.ack_num,
            hdr.tcp.data_offset,
            hdr.tcp.reserved,
            hdr.tcp.ctl_flag,
            hdr.tcp.window_size,
            hdr.tcp.urgent_num,
            meta.tcp_nop,
            meta.tcp_nop,
            meta.tcp_ts,
            meta.tcp_ts_len,
            meta.tcp_ts_ts_val,
            meta.tcp_ts_ts_ecr,
            hdr.tcp_options_padding.padding
        }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcp_options_vec);
        packet.emit(hdr.tcp_options_padding);
        packet.emit(hdr.adder);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
