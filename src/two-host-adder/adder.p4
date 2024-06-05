
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

// the address of hosts
const bit<48> HOST_1_ADDR         = 0x080000000101;
const bit<48> HOST_2_ADDR         = 0x080000000102;
const bit<48> HOST_3_ADDR         = 0x080000000103;
const bit<48> HOST_4_ADDR         = 0x080000000104;
const bit<48> DST_MAC             = 0x080000000105;
const bit<32> HOST_1_IP           = 0x0a000101;
const bit<32> HOST_2_IP           = 0x0a000102;
const bit<32> HOST_3_IP           = 0x0a000103;
const bit<32> HOST_4_IP           = 0x0a000104;
const bit<32> DST_IP              = 0x0a000105;
const bit<9>  HOST_1_PORT         = 1;
const bit<9>  HOST_2_PORT         = 2;
const bit<9>  HOST_3_PORT         = 3;
const bit<9>  HOST_4_PORT         = 4;
const bit<9>  DST_PORT            = 5;

// buffer size
const bit<32> BUFFER_SIZE         = 128;

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
    bit<16> ipv4_totalLen;
    bit<16> tcp_length; // tcp header length using at checksum calculation
    bit<16> tot_length; // total length with adder header 
    bit<1>  ack_valid;
    bit<1>  sack_valid;
    bit<32> h1_tcp_seqnum;
    bit<32> h2_tcp_seqnum;
    bit<32> h3_tcp_seqnum;
    bit<32> h4_tcp_seqnum;
    bit<32> h1_tcp_acknum;
    bit<32> h2_tcp_acknum;
    bit<32> h3_tcp_acknum;
    bit<32> h4_tcp_acknum;
    bit<16> h1_tcp_port;
    bit<16> h2_tcp_port;
    bit<16> h3_tcp_port;
    bit<16> h4_tcp_port;
    bit<32> seq_num;
}
parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         inout metadata meta,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
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
        meta.sack_valid=1;
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * (bit<32>)n_sack_bytes - 16));
        transition next_option;
    }
    state parse_tcp_option_ts {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.ts);
        transition next_option;
    }
    state consume_remaining_tcp_hdr_and_accept {
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
        meta.ipv4_totalLen = hdr.ipv4.totalLen;
        transition select(hdr.ipv4.protocol) {
            //TYPE_UDP  : parse_udp;
            TYPE_TCP  : parse_tcp;
            default   : accept;
        }
    }
    state parse_tcp{
        packet.extract(hdr.tcp);
        meta.tcp_length = (bit<16>)hdr.tcp.data_offset * 4;
        meta.tot_length = hdr.ipv4.totalLen-20;
        Tcp_option_parser.apply(packet, hdr.tcp.data_offset,meta,
                                hdr.tcp_options_vec, hdr.tcp_options_padding);
        transition select(hdr.ipv4.totalLen - 20 - meta.tcp_length) {
            0 : accept;
            default : parse_adder;
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
    register<bit<32>>(10)  init_seq_num;
    register<bit<1>> (10)  init_seq_num_valid;
    register<bit<32>>(10)  init_ack_num;
    register<bit<16>>(10)  host_tcp_port;         //store tcp port of every host

    //three type of table
    //First is seq_num, and should be changed to ring buffer as index
    //Second is num, the sum of result is stored in this table
    //Third is bit_set, to record which host has already sent the result 
    register<bit<32>>(BUFFER_SIZE) seq_num_buffer;
    register<bit<32>>(BUFFER_SIZE) num_buffer;
    register<bit<4>> (BUFFER_SIZE) bit_set_buffer;

    // three variables as pointer to the buffer
    // min_index: point to the smallest seq that 
    //            has not been acked
    // max_index: point to the biggest seq
    register<bit<32>>(1) min_index;
    register<bit<32>>(1) max_index;

    // debug register
    register<bit<32>>(1) debug_seq_num;

    action drop() {
        // drop the packet
        mark_to_drop(standard_metadata);
    }
    action send_result(bit<9> port) {
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
        // read debug register
        bit<32> debug_seq_num_val;
        debug_seq_num.read(debug_seq_num_val, 0);

        //ack part, cna only be triggered when 4 host all initialized 
        //metadata is used to store the tcp inform of each host
        if(standard_metadata.ingress_port==DST_PORT && hdr.tcp.isValid()){
            bit<1> h1_valid;
            bit<1> h2_valid;
            bit<1> h3_valid;
            bit<1> h4_valid;
            init_seq_num_valid.read(h1_valid,1);
            init_seq_num_valid.read(h2_valid,2);
            init_seq_num_valid.read(h3_valid,3);
            init_seq_num_valid.read(h4_valid,4);
            if(h1_valid==1 && h2_valid==1 && h3_valid==1 && h4_valid==1){
                bit<32> ini_seq_num;
                init_seq_num.read(ini_seq_num,1);

                // debug
                debug_seq_num.write(0, hdr.tcp.ack_num - ini_seq_num);

                bit<32> relative_seq_num=((hdr.tcp.ack_num-ini_seq_num)>>10);
                if(relative_seq_num>0){
                    meta.ack_valid=1;
                    meta.seq_num=relative_seq_num;
                    init_seq_num.read(meta.h1_tcp_seqnum,1);
                    init_seq_num.read(meta.h2_tcp_seqnum,2);
                    init_seq_num.read(meta.h3_tcp_seqnum,3);
                    init_seq_num.read(meta.h4_tcp_seqnum,4);
                    init_ack_num.read(meta.h1_tcp_acknum,1);
                    init_ack_num.read(meta.h2_tcp_acknum,2);
                    init_ack_num.read(meta.h3_tcp_acknum,3);
                    init_ack_num.read(meta.h4_tcp_acknum,4);
                    host_tcp_port.read(meta.h1_tcp_port,1);
                    host_tcp_port.read(meta.h2_tcp_port,2);
                    host_tcp_port.read(meta.h3_tcp_port,3);
                    host_tcp_port.read(meta.h4_tcp_port,4);
                    multicast();

                    // increase min_index to the next seq_num
                    bit<32> min_index_val;
                    bit<32> min_seq;
                    bit<32> diff;
                    min_index.read(min_index_val, 0);
                    seq_num_buffer.read(min_seq, min_index_val);
                    diff = relative_seq_num - min_seq;
                    if (diff >= 0) {
                        min_index.write(0, (min_index_val + diff + 1) % BUFFER_SIZE);
                    }
                }        
            }
        }
        if(hdr.adder.isValid()){
            //sequence number calculation
            bit<1> init_valid;
            bit<9> in_port=standard_metadata.ingress_port;
            bit<32> seq_num;
            bit<32> relative_seq_num=0;
            init_seq_num_valid.read(init_valid,(bit<32>)in_port);
            //initialize the first seq_num and ack_num of each host with adder header
            if(init_valid==0){
                init_seq_num.write((bit<32>)in_port, hdr.tcp.seq_num);
                init_ack_num.write((bit<32>)in_port, hdr.tcp.ack_num);
                init_seq_num_valid.write((bit<32>)in_port, 1);
                host_tcp_port.write((bit<32>)in_port, hdr.tcp.srcPort);
                relative_seq_num=1;
            }
            else{
                init_seq_num.read(seq_num,(bit<32>)in_port);
                relative_seq_num=((hdr.tcp.seq_num-seq_num)>>10)+1;

                // debug
                debug_seq_num.write(0, hdr.tcp.seq_num - seq_num);
            }
            
            //the relative sequence num->ring buffer index
            // "min_seq", "max_seq" are the corresponding value of 
            // index "min_index", "max_index" in the ring buffer 
            // "seq_num_buffer".
            bit<32> min_index_val;
            bit<32> max_index_val;
            min_index.read(min_index_val, 0);
            max_index.read(max_index_val, 0);
            bit<32> min_seq;
            bit<32> max_seq;
            seq_num_buffer.read(min_seq, min_index_val);
            if (max_index_val == 0) {
                seq_num_buffer.read(max_seq, BUFFER_SIZE - 1);
                max_seq = max_seq + 1;
            }
            else {
                seq_num_buffer.read(max_seq, max_index_val - 1);
                max_seq = max_seq + 1;
            }
            bit<32> ring_buffer_index = (relative_seq_num - 1) % BUFFER_SIZE;
            // if the relative sequence number has already been acked
            if (relative_seq_num < min_seq) {
                drop();
            } 
            // else if the result is on the way to receiver
            // or "relative_seq_num" is aggregating
            else if (relative_seq_num >= min_seq && relative_seq_num < max_seq) {
                //number buffer operation
                bit<32> num;  //current sum of this seq_num
                bit<4> state; //current state of this seq_num
                num_buffer.read(num,ring_buffer_index);
                bit_set_buffer.read(state,ring_buffer_index);
                if(in_port==1){
                    //mask is used to decide this host has already sent the result
                    bit<4> mask=0x1;  
                    //use & operation to decide whether this packet should be handled
                    if((state&mask)==0){
                        num_buffer.write(ring_buffer_index, num+hdr.adder.num);
                        bit_set_buffer.write(ring_buffer_index, state+1);
                        seq_num_buffer.write(ring_buffer_index, relative_seq_num);
                    }
                }
                else if(in_port==2){
                    bit<4> mask=0x2;
                    if((state&mask)==0){
                        num_buffer.write(ring_buffer_index, num+hdr.adder.num);
                        bit_set_buffer.write(ring_buffer_index, state+2);
                        seq_num_buffer.write(ring_buffer_index, relative_seq_num);
                    }
                }
                else if(in_port==3){
                    bit<4> mask=0x4;
                    if((state&mask)==0){
                        num_buffer.write(ring_buffer_index, num+hdr.adder.num);
                        bit_set_buffer.write(ring_buffer_index, state+4);
                        seq_num_buffer.write(ring_buffer_index, relative_seq_num);
                    }
                }
                else if(in_port==4){
                    bit<4> mask=0x8;
                    if((state&mask)==0){
                        num_buffer.write(ring_buffer_index, num+hdr.adder.num);
                        bit_set_buffer.write(ring_buffer_index, state+8);
                        seq_num_buffer.write(ring_buffer_index, relative_seq_num);
                    }
                }
                bit_set_buffer.read(state,ring_buffer_index);
                //when state is 0xf(1111), it means all host has sent the result
                //then we can send the result to the host
                if(state==0xf){
                    bit<32> h1_tcp_seq_num;
                    init_seq_num.read(h1_tcp_seq_num,1);
                    //here the tcp seq_num of each host is the first seq_num with adder header,
                    //so here should minus 1 to get the correct seq_num
                    h1_tcp_seq_num=h1_tcp_seq_num+((relative_seq_num-1)<<10);
                    hdr.tcp.seq_num=h1_tcp_seq_num;
                    init_ack_num.read(hdr.tcp.ack_num,1);
                    host_tcp_port.read(hdr.tcp.srcPort,1);
                    num_buffer.read(hdr.adder.num,ring_buffer_index);
                    hdr.ipv4.srcAddr=HOST_1_IP;
                    hdr.ethernet.srcAddr=HOST_1_ADDR;
                    standard_metadata.egress_spec=5;

                    // clear num_buffer and bit_set_buffer after done aggregation
                    num_buffer.write(ring_buffer_index, 0);
                    bit_set_buffer.write(ring_buffer_index, 0);
                }
                else{
                    drop();
                }
            }
            // else if the "relative_seq_num" has not been seen yet
            else // relative_seq_num >= max_seq
            {
                // if the buffer is not full, update the buffer
                if (max_seq <= relative_seq_num && relative_seq_num < BUFFER_SIZE + min_seq - 1 || max_index_val == min_index_val) {
                    seq_num_buffer.write(ring_buffer_index, relative_seq_num);
                    num_buffer.write(ring_buffer_index, hdr.adder.num);
                    // bit_set_buffer.write(ring_buffer_index, (bit<4>)(1) << (in_port - 1));
                    if (in_port == 1) {
                        bit_set_buffer.write(ring_buffer_index, 1);
                    } else if (in_port == 2) {
                        bit_set_buffer.write(ring_buffer_index, 2);
                    } else if (in_port == 3) {
                        bit_set_buffer.write(ring_buffer_index, 4);
                    } else if (in_port == 4) {
                        bit_set_buffer.write(ring_buffer_index, 8);
                    }
                    max_index.write(0, (ring_buffer_index + 1) % BUFFER_SIZE);
                }
                else {
                    drop();
                }
            }
        }
        else{
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
        if(standard_metadata.egress_port==standard_metadata.ingress_port){
            drop();
        }
        if(meta.ack_valid==1&&standard_metadata.egress_port==2){
            hdr.tcp.ack_num = meta.h2_tcp_seqnum+(meta.seq_num<<10);
            hdr.tcp.seq_num = meta.h2_tcp_acknum;
            hdr.tcp.dstPort = meta.h2_tcp_port;
            meta.h2_tcp_acknum=hdr.tcp.ack_num;
            meta.h2_tcp_seqnum=hdr.tcp.seq_num;
            hdr.ipv4.dstAddr = HOST_2_IP;
            hdr.ethernet.dstAddr = HOST_2_ADDR;
        }
        if(meta.ack_valid==1&&standard_metadata.egress_port==3){
            hdr.tcp.ack_num = meta.h3_tcp_seqnum+(meta.seq_num<<10);
            hdr.tcp.seq_num = meta.h3_tcp_acknum;
            hdr.tcp.dstPort = meta.h3_tcp_port;
            meta.h3_tcp_acknum=hdr.tcp.ack_num;
            meta.h3_tcp_seqnum=hdr.tcp.seq_num;
            hdr.ipv4.dstAddr = HOST_3_IP;
            hdr.ethernet.dstAddr = HOST_3_ADDR;
        }
        if(meta.ack_valid==1&&standard_metadata.egress_port==4){
            hdr.tcp.ack_num = meta.h4_tcp_seqnum+(meta.seq_num<<10);
            hdr.tcp.seq_num = meta.h4_tcp_acknum;
            hdr.tcp.dstPort = meta.h4_tcp_port;
            meta.h4_tcp_acknum=hdr.tcp.ack_num;
            meta.h4_tcp_seqnum=hdr.tcp.seq_num;
            hdr.ipv4.dstAddr = HOST_4_IP;
            hdr.ethernet.dstAddr = HOST_4_ADDR;
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
            hdr.tcp_options_padding.padding,
            hdr.adder.num
        }, hdr.tcp.checksum, HashAlgorithm.csum16);
        //I found that if the ack packet including the window update message,
        //TCP optiona will includes the SACK, so here should use meta.sack_valid to decide
        //whether the SACK option should be included in the checksum calculation
        //meta.sack_valid is set in TCP_subparser
        update_checksum(meta.ack_valid==1 && meta.sack_valid==0, {
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
            hdr.tcp_options_padding.padding
        }, hdr.tcp.checksum, HashAlgorithm.csum16);
        //Once TCP options includes SACK messages, the option stack will be
        //NOP+NOP+SACK, so I directly use the stacks index to calculate the checksum
        update_checksum(meta.ack_valid==1 && meta.sack_valid==1, {
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
            hdr.tcp_options_vec[0].nop,
            hdr.tcp_options_vec[1].nop,
            hdr.tcp_options_vec[2].sack,
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
