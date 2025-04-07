#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arg():
    parser=optparse.OptionParser()
    parser.add_option("-t","--target",dest="target",help="Target Ip range")
    options,arguments=parser.parse_args()
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered =scapy.srp(arp_req_broadcast, timeout=1 , verbose=False) [0]
    print(answered[0][1].hwsrc)
    
    
    clients=[]
    
    for element in answered:
        client_dict={"ip": element[1].psrc,"mac": element[1].hwsrc}
        clients.append(client_dict)
    return clients
    
def print_results(result_list):
     print("IP\t\t\tMAC Address\n-----------------------------------------------")
     for client in result_list:
         print(client["ip"] + "\t\t" + client["mac"]) 
    
options = get_arg()
scan_result= scan(options.target)
print_results(scan_result)
