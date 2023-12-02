# brokent - Network Security and Attack Testing Python Script

##

Brokeint software is a script written in Python language with network discovery, scanning, information, SSID scanning and DOS attack capabilities.
##

## Use

### Help Documentation

`python3 brokeint.py -h`

###  Scans devices with cidr display and gives information about devices 

`python3 brokeint.py -ip 192.168.1.1/24 -iface eth0,Wi-Fi`

### The --nmap parameter scans using nmap and collects information about devices

`python3 brokeint.py -ip 192.168.1.1/24 --nmap`

### Warns the client against MITM attacks when accessing http sites

`
python3 brokeint.py -M -iface Wi-Fi`

### Brings detailed information about networks and SSID around

`python3 brokeint.py --network`

### Shell opens and provides information about your own network with commands from the help documentation

`python3 brokeint.py --networkPassword`

### This command deauts the desired target and tries to interrupt its internet service

`python3 brokeint.py --deauth <packet_count> -a <modem(SSID)_mac> -c <target_mac> -iface Wi-Fi`

### Ping of death sends ICMP pings to the target and performs a DOS attack

`python3 brokeint.py ip <target_ip> -d 150 -C 10000 -iface Wi-Fi`

### Land attack (designed for Microsoft Windows): performs a DOS attack by making the attack on the local network

`python3 brokeint.py -sI <source_ip> -dI <destination_ip> -C 1000`
