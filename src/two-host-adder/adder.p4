/* -*- P4_16 -*- */

/*
        1               2               3               4
+---------------+---------------+---------------+---------------+
|      'A'      |      'D'      | VERSION_MAJOR | VERSION_MINOR |
+---------------+---------------+---------------+---------------+
|    SEQ_NUM    |
+---------------------------------------------------------------+
|                              NUM                              |
+---------------------------------------------------------------+
*/

#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */

/*
 * Standard Ethernet header
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * This is a custom protocol header for the calculator. We'll use
 * etherType 0x1234 for it (see parser)
 */
const bit<16> ADDER_ETYPE         = 0x1234;
const bit<8>  ADDER_A             = 0x41;
const bit<8>  ADDER_D             = 0x44;
const bit<8>  ADDER_VERSION_MAJOR = 0x00;
const bit<8>  ADDER_VERSION_MINOR = 0x01;

// the address of host 3
const bit<48> ADDER_DST_ADDR      = 0x080000000103;
const bit<9>  ADDER_DST_PORT      = 3;

header adder_t {
    bit<8>  a;
    bit<8>  d;
    bit<8>  ver_maj;
    bit<8>  ver_min;
    bit<8>  seq_num;
    bit<32> num;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    adder_t      adder;
}

/*
 * All metadata, globally used in the program, also  needs to be assembled
 * into a single struct. As in the case of the headers, we only need to
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */

struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ADDER_ETYPE : check_adder;
            default     : accept;
        }
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

    register<bit<32>>(256) num_buffer;
    register<bit<1>> (256) num_buffer_valid;

    action send_dest(bit<32> result, bit<8> seq_num) {
        // save the result in header
        hdr.adder.num = result;
        hdr.adder.seq_num = seq_num;

        // forward the packet to the destination
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = ADDER_DST_ADDR;
        hdr.ethernet.etherType = ADDER_ETYPE;
        standard_metadata.egress_spec = ADDER_DST_PORT;
    }
    action save_num(bit<32> index, bit<32> num) {
        num_buffer.write(index, num);
        num_buffer_valid.write(index, 1);
    }
    action delete_num(bit<32> index) {
        num_buffer.write(index, 0);
        num_buffer_valid.write(index, 0);
    }

    action operation_drop() {
        // drop the packet
        mark_to_drop(standard_metadata);
    }

    apply {
        if (hdr.adder.isValid()) {
            // read the number from the register
            bit<32> num;
            bit<1>  valid;
            bit<24> padding = 0x0;
            bit<32> index = padding ++ hdr.adder.seq_num;
            num_buffer.read(num, index);
            num_buffer_valid.read(valid, index);

            // based on valid, determine what to do:
            // 1. if valid == 0, then the register is empty, so we need to
            //    buffer the number and wait for the next packet
            // 2. if valid == 1, then the register is full, so we can
            //    proceed with the calculation\
            bit<1> write_valid;
            bit<32> write_num;
            if (valid == 0) {
                // buffer the number
                save_num(index, hdr.adder.num);
            } else {
                // calculate the result
                bit<32> result = num + hdr.adder.num;
                // send the result back
                send_dest(result, hdr.adder.seq_num);
                // clear the register
                delete_num(index);
            }
        } else {
            operation_drop();
        }
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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
