#include <core.p4>
#include <v1model.p4>


const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 9

register<bit<32>>(10) path;

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
    bit<4>      num;
    bit<32>     val1;
    bit<32>     val2;
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
        // next = stack[nextIndex] then nextIndex += 1
        // last = stack[nextIndex - 1]
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

    action set_path(
        bit<4>num,
        bit<32>port1,
        bit<32>port2,
        bit<32>port3,
        bit<32>port4,
        bit<32>port5,
        bit<32>port6,
        bit<32>port7,
        bit<32>port8,
        bit<32>port9){
            path.write((bit<32>)0, (bit<32>)num);
            path.write((bit<32>)1, (bit<32>)port1);
            path.write((bit<32>)2, (bit<32>)port2);
            path.write((bit<32>)3, (bit<32>)port3);
            path.write((bit<32>)4, (bit<32>)port4);
            path.write((bit<32>)5, (bit<32>)port5);
            path.write((bit<32>)6, (bit<32>)port6);
            path.write((bit<32>)7, (bit<32>)port7);
            path.write((bit<32>)8, (bit<32>)port8);
            path.write((bit<32>)9, (bit<32>)port9);
            meta.num = 1;

    }

    action AddHeader(bit<15> port, bit<1> flag){
        hdr.ethernet.etherType = TYPE_SRCROUTING;
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
            set_path;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 512;
        const default_action = _drop();
    }

    apply {
        if (hdr.ethernet.etherType == TYPE_IPV4 && meta.num == 0){
            ipv4_lpm.apply();
        }

        if(meta.num != (bit<4>)0){
            // length of path
            path.read(meta.val1, (bit<32>)0);
            //1
            path.read(meta.val2, (bit<32>)meta.num);
            AddHeader((bit<15>)meta.val2, 1);
            if((bit<32>)meta.num != meta.val1){
                meta.num = meta.num + 1;
            }else{
                meta.num = 15;
            }
        

            //2
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //3
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //4
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //5
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //6
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //7
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //8
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }

            //9
            if(meta.num != 15){
                path.read(meta.val2, (bit<32>)meta.num);
                AddHeader((bit<15>)meta.val2, 0);
                if((bit<32>)meta.num != meta.val1){
                    meta.num = meta.num + 1;
                }else{
                    meta.num = 15;
                }
            }
        }

        if(hdr.srcRoutes[0].isValid()){
            if (hdr.srcRoutes[0].bos == 1){
                srcRoute_finish();
            }
            srcRoute_nhop();
            if(hdr.ipv4.isValid()){
                update_ttl();
            }
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
