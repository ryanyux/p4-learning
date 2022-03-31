#!/usr/bin/python

from mininet.node import Docker
from mininet.net import Containernet
from mininet.link import Link,TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def topology():
    net = Containernet()
    
    print("add hosts")
    h1 = net.addHost("h1",ip="192.168.0.1/24")
    h2 = net.addHost("h2",ip="192.168.0.2/24")
    br1 = net.addHost("br1")
    r1 = net.addHost("r1",ip="192.168.0.254/24")
    d1 = net.addDocker("d1",ip="10.0.0.1/24",dimage="ubuntu:trusty")

    print("add links")
    
    net.addLink(h1,br1)
    net.addLink(h2,br1)
    net.addLink(r1,br1)
    net.addLink(r1,d1)
    
    net.start()
    d1.cmd("/etc/init.d/ssh start")
    
    r1.cmd("ifconfig r1-eth1 0")
    r1.cmd("ip addr add 10.0.0.2/24 brd + dev r1-eth1")
    r1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
    r1.cmd("iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -o r1-eth1 -j MASQUERADE")
    
    h1.cmd("ip route add default via 192.168.0.254")
    
    br1.cmd("ifconfig br1-eth0 0")
    br1.cmd("ifconfig br1-eth0 1")
    br1.cmd("ifconfig br1-eth0 2")
    
    br1.cmd("brctl addbr br1")
    br1.cmd("brctl addif br1 br1-eth0")
    br1.cmd("brctl addif br1 br1-eth1")
    br1.cmd("brctl addif br1 br1-eth2")
    br1.cmd("ifconfig br1 up")
    
    
    
    print("***RUNNING****")
    
    CLI(net)
    net.stop()

if __name__ == "__main__":
    topology()

