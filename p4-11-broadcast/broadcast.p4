 /* -*- P4_16 -*- */
 #include <core.p4>
 #include <v1model.p4>

 /*************************************************************************
 *********************** H E A D E R S  ***********************************
 *************************************************************************/

header ethernet_t {
 		bit<48> dstAddr;
 		bit<48> srcAddr;
 		bit<16>   etherType;
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
    bit<32> srcAddr;
    bit<32> dstAddr;
}
 
 struct metadata {
 		/* empty */
 }

 

 struct headers {
 	ethernet_t   ethernet;
	ipv4_t     ipv4;
 }

 

 /*************************************************************************
 *********************** P A R S E R  ***********************************
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
			transition select(hdr.ethernet.etherType) {
            	16w0x800: parse_ipv4;
            	default: accept;
        	}
 		}
		state parse_ipv4 {
        	packet.extract(hdr.ipv4);
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

 		action forward(bit<9> port) {
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

		/*
		* BROADCAST
		*
		*/
		action broadcast(bit<16> mcast_grp_id){
			standard_metadata.mcast_grp = mcast_grp_id;
		}
		table ip_broadcast{
			key = {
				hdr.ipv4.dstAddr:exact;
				standard_metadata.ingress_port:exact;
			}

			actions = {
				broadcast;
				NoAction;
			}
			size = 1024;
			default_action = NoAction();
		}

 		apply {
			if (!ip_broadcast.apply().hit){
 				mac_forward.apply();
			}
 		}
 }

 /*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

 control MyEgress(inout headers hdr,
 								inout metadata meta,
 								inout standard_metadata_t standard_metadata) {
 		apply {  }
 }

 /*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

 control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
 		apply {
 		}
 }

 /*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/

 control MyDeparser(packet_out packet, in headers hdr) {
 		apply {
 			packet.emit(hdr.ethernet);
			packet.emit(hdr.ipv4);
 		}
 }

 /*************************************************************************
 ***********************  S W I T C H  *******************************
 *************************************************************************/

 V1Switch(
 MyParser(),
 MyVerifyChecksum(),
 MyIngress(),
 MyEgress(),
 MyComputeChecksum(),
 MyDeparser()

 ) main;