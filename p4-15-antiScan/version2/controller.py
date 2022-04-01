
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
#from scapy.all import Ether, sniff, Packet, BitField
from scapy.all import *

from collections import Counter
syn_cnt= Counter()
syn_ack_cnt= Counter()
blockip = []

class myController(object):

    def __init__(self):
        self.topo = load_topo("topology.json")
        self.controllers = {}
        self.connect_to_switches()
        self.stat = {}
        
    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            #print "p4switch:", p4switch, "thrift_port:", thrift_port
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port) 	

    def recv_msg_cpu(self, pkt):
        print("-------------------------------------------------------------------")
        global rules
        print("interface:", pkt.sniffed_on)
        print("summary:", pkt.summary())
        var1 = 0
        var2 = 0
        src = str(pkt[IP].src)
        dst = str(pkt[IP].dst)
        if TCP in pkt:     
            if pkt[TCP].flags == 0x02:
                syn_cnt[(src, dst)] += 1
                var1 = syn_cnt[(src, dst)]
                print("SYN ",src, " ===> ",dst," : ",var1)
            elif pkt[TCP].flags == 0x12:
                syn_ack_cnt[(dst, src)] += 1
                var2 =  syn_ack_cnt[(dst, src)]
                print("SYN ",dst, " ===> ",src," : ",var2)
        
            if var1 > var2 + 3:
                if src not in blockip:
                    blockip.append(src)
                    self.controllers["s1"].table_add("block_pkt", "drop", [src], [])
      
    def run_cpu_port_loop(self):
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        print(cpu_interfaces)
        sniff(iface=cpu_interfaces, prn=self.recv_msg_cpu)
        
if __name__ == "__main__":
    controller = myController()
    controller.run_cpu_port_loop()