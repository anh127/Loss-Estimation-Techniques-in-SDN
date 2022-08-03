import time
from scapy.all import Ether,IP,UDP,send
import time
import sys

pkt = IP(dst="10.255.255.255")/UDP(dport=65534) #Simulating actual traffic


while 1:
    send(pkt, verbose=False)

    #Wait for all OFSs receive the flow entries
    time.sleep(1)

   
    send(pkt, loop = 1, inter=1.0/1000, verbose=False) 
    
