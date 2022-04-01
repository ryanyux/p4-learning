/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16>   TYPE_IPV4   = 0x800;
const bit<8>    TCP         = 0x06;
const bit<8>    UDP         = 0x11;
const bit<8>    SYN         = 0x02;
const bit<8>    SYN_ACK     = 0x12;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}
struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    tcp_t           tcp;
}


struct metadata {
    bit<10> flowHash;
    bit<10> syn_cnt;
    bit<10> syn_ack_cnt;
}

/*************************************************************************
************   MY PARSER  *************
*************************************************************************/


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        log_msg("PROTOCOL {}",{hdr.ipv4.protocol});
        transition select(hdr.ipv4.protocol){
            TCP:        parse_tcp;
            UDP:        parse_udp;
            default:    accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

    }

    action add_syn_cnt(){
        hash(meta.flowHash,HashAlgorithm.crc16,16w0,{hdr.ipv4.srcAddr},32w100);
        syn_cnt.read(meta.syn_cnt, (bit<32>)meta.flowHash);
        meta.syn_cnt = meta.syn_cnt + 1;
        syn_cnt.write((bit<32>)meta.flowHash, meta.syn_cnt);
    }

    action add_syn_ack_cnt(){
        hash(meta.flowHash,HashAlgorithm.crc16,16w0,{hdr.ipv4.dstAddr},32w100);
        syn_ack_cnt.read(meta.syn_ack_cnt, (bit<32>)meta.flowHash);
        meta.syn_ack_cnt = meta.syn_ack_cnt + 1;
        syn_ack_cnt.write((bit<32>)meta.flowHash, meta.syn_ack_cnt);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    apply {
        bit<1> isDrop = 0;
        if(hdr.tcp.isValid()){
            if(hdr.tcp.flags == SYN){
                add_syn_cnt();
                bit<10> var1;
                bit<10> var2;

                syn_cnt.read(var1, (bit<32>)meta.flowHash);
                syn_ack_cnt.read(var2, (bit<32>)meta.flowHash);

                if(var1 >= var2 + 3){
                    isDrop = 1;
                }
            }else if(hdr.tcp.flags == SYN_ACK){
                add_syn_ack_cnt();
            }
        }
        if(hdr.ipv4.isValid() && isDrop == 0){
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
                     apply{}
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
              hdr.ipv4.hdrChecksum,
              HashAlgorithm.csum16);
    }
}
/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/



/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;