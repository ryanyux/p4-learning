/*-*-P4_16-*-*/
#include<core.p4>
#include<v1model.p4>

header ethernet_t{
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

struct metadata {}

struct headers{
    ethernet_t ethernet;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){

    state start{
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition accept;
    }

}

control MyIngress(inout headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){
    action drop(){
        mark_to_drop(standard_metadata);
    }

    action forward(bit<9> port){
        standard_metadata.egress_spec = port;
    }

    table mac_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    apply{
        mac_forward.apply();
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta){
    apply{}
}

control MyComputeChecksum(inout headers hdr, inout metadata meta){
    apply{}
}

control MyEgress(inout headers hdr, inout metadata meta,
                inout standard_metadata_t std_meta){
    apply{}
}
control MyDeparser(packet_out packet, in hearders hdr){
    apply{
        packet.emit(hdr.ethernet);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;