#!/usr/bin/env python

import scapy.all as scapy
import argparse
import os


os.system('clear')

def get_argumentos():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Especifique su IP objetivo o rango de IP")
    options = parser.parse_args()
    return  options

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
    client_list = []

    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        client_list.append(client_dict)

    return client_list

def print_result(scan_list):
    print ("\u001b[31m   _____             _          _____                      _ _         ")
    print ("\u001b[31m  |  __ \           | |        / ____|                    (_) |        ")
    print ("\u001b[31m  | |  | | __ _ _ __| |_ _____| (___   ___  ___ _   _ _ __ _| |_ _   _ ")
    print ("\u001b[31m  | |  | |/ _` | '__| __|______\___ \ / _ \/ __| | | | '__| | __| | | |")
    print ("\u001b[31m  | |__| | (_| | |  | |_       ____) |  __/ (__| |_| | |  | | |_| |_| |")
    print ("\u001b[31m  |_____/ \__,_|_|   \__|     |_____/ \___|\___|\__,_|_|  |_|\__|\__, |")
    print ("\u001b[31m                                                                  __/ |")
    print ("\u001b[31m                 www.hc-security.com.mx       by:Equinockx       |___/ ")
    print ("\u001b[31m                                                                       ")
    
    
    print ("\t\t \u001b[36mIP\t\t\t\t \u001b[32m MAC\n\t \u001b[34m -------------------------------------------------------")
    for cliente in scan_list:
        print ("\t\t" + cliente["IP"] + "\t\t\t" + cliente["MAC"])

options = get_argumentos()
result_list = scan(options.target)
print_result(result_list)





