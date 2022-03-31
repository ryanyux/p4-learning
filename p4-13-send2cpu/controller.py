
from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import SimpleSwitchThriftAPI
#from scapy.all import Ether, sniff, Packet, BitField
from scapy.all import *

rules=[]

class myController(object):

    def __init__(self):
        self.topo = load_topo("topology.json")
        self.controllers = {}
        self.connect_to_switches()
        
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
        if IP in pkt:
            ip_src=pkt[IP].src
            ip_dst=pkt[IP].dst
            print("ip_src:", ip_src, " ip_dst:", ip_dst)
            if (ip_src, ip_dst) not in rules:
                rules.append((ip_src, ip_dst))
                print("rules:", rules)
            else:
                return 
       
        switches = {sw_name:{} for sw_name in self.topo.get_p4switches().keys()}
        #print "switches:", switches
        for sw_name, controller in self.controllers.items():
            for host in self.topo.get_hosts_connected_to(sw_name):
                host_ip_addr = self.topo.get_host_ip(host)
                if ip_src == host_ip_addr:
                    sw_src = sw_name
             
                if ip_dst == host_ip_addr:
                    sw_dst = sw_name  
                    sw_port = self.topo.node_to_node_port_num(sw_name, host)
                    host_ip = self.topo.get_host_ip(host) + "/32"
                    host_mac = self.topo.get_host_mac(host)
             #print host, "(", host_ip, host_mac, ")", "-->", sw_name, "with port:", sw_port
 
             #add rule
                    print("table_add at {}:".format(sw_name))
                    self.controllers[sw_name].table_add("ipv4_lpm", "ipv4_forward", [str(host_ip)], [str(host_mac), str(sw_port)])
             
        print("sw_src:", sw_src, "sw_dst:", sw_dst) 
        paths = self.topo.get_shortest_paths_between_nodes(sw_src, sw_dst)
        sw_1=sw_src
        for next_hop in paths[0][1:]:
            host_ip = ip_dst + "/32"
            sw_port = self.topo.node_to_node_port_num(sw_1, next_hop)
            dst_sw_mac = self.topo.node_to_node_mac(next_hop, sw_1)
            #add rule
            print ("table_add at {}:".format(sw_1))
            self.controllers[sw_1].table_add("ipv4_lpm", "ipv4_forward", [str(host_ip)],
                                                    [str(dst_sw_mac), str(sw_port)])
            sw_1=next_hop

        print("send original packet back from ", pkt.sniffed_on)
        sendp(pkt, iface=pkt.sniffed_on, verbose=False)
            

 
      
    def run_cpu_port_loop(self):
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.recv_msg_cpu)
        
if __name__ == "__main__":
    controller = myController()
    controller.run_cpu_port_loop()