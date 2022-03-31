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
    d1 = net.addDocker("d1",ip="192.168.0.2/24",dimage="ubuntu:trusty")
    
    print("add links")
    net.addLink(h1,d1)
    net.start()
    d1.cmd("/etc/init.d/ssh start")
    
    print("***RUNNING****")
    
    CLI(net)
    net.stop()

if __name__ == "__main__":
    topology()

