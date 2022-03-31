#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 2

typedef bit<48> macAddr_t;
typedef bit<9> egressSpec_t;
typedef bit<32> ip4Addr_t;
  
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header srcRoute_t {
    bit<1> bos;// 1 = last one
    bit<15> port;
}
 
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
 
struct metadata {
}
 
struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
}
 
parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_srcRouting{
        packet.extract(hdr.srcRoutes.next);
        transition select(hdr.srcRoutes.last.bos){
            1: parse_ipv4;
            default: parse_srcRouting;
        }
    }

}
 
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    
    action dmac(macAddr_t dstAddr){
        hdr.ethernet.dstAddr = dstAddr;
    }

    table ipv4_final {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            dmac;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }


    apply {
        ipv4_final.apply();
    }
}
 
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

    action srcRoute_nhop(){
        standard_metadata.egress_spec = (bit<9>) hdr.srcRoutes[0].port;
        hdr.srcRoutes.pop_front(1);
    }

    action srcRoute_finish(){
        hdr.ethernet.etherType = TYPE_IPV4;
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action AddHeader(bit<15> port, bit<1> flag){
        hdr.ethernet.etherType = TYPE_SRCROUTING;
        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port;
        hdr.srcRoutes[0].bos = flag;
    }

    action AddHeader2(bit<15> port, bit<1> flag){
        hdr.srcRoutes.push_front(1);
        hdr.srcRoutes[0].setValid();
        hdr.srcRoutes[0].port = port;
        hdr.srcRoutes[0].bos = flag;
    }
    @name("._drop") action _drop() {
        mark_to_drop(standard_metadata);
    }
    table ipv4_lpm {
        actions = {
            AddHeader;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 512;
        const default_action = _drop();
    }

    table ipv4_lpm2{
        actions = {
            AddHeader2;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
        const default_action = _drop();
    }
    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4){
            ipv4_lpm.apply();
            ipv4_lpm2.apply();
        }
        
        if (hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();// set ethernetType to IPV4
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }else{
            _drop();
        }
    }
}
 
control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}
 
control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}
 
control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            true, 
        {hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
         hdr.ipv4.hdrChecksum, 
         HashAlgorithm.csum16);
    }
}
 
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
