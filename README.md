# DeuthAtt-ReconNetwork

##windows compatible

=> pip3 install -r requirements.txt

Other requirements => winpcap.exe and libpcap.exe


#################


HELP DOCUMENTATION


#######################


if #!/usr/bin/python3:

python3 brokeint.py -h   => shows help documentation

python3 brokeint.py -ip 192.168.1.1/24 -iface eth0,Wi-Fi  => Scans devices with cidr display and gives information about devices

python3 brokeint.py -ip 192.168.1.1/24 --nmap  => The --nmap parameter scans using nmap and collects information about devices

python3 brokeint.py -M -iface Wi-Fi  => Warns the client against MITM attacks when accessing http sites

python3 brokeint.py --network  => Brings detailed information about networks and SSID around

python3 brokeint.py --networkPassword  => Shell opens and provides information about your own network with commands from the help documentation

python3 brokeint.py --deauth <packet_count> -a <modem(SSID)_mac> -c <target_mac> -iface Wi-Fi  => This command deauts the desired target and tries to interrupt its internet service



Else:


python brokeint.py -h   => shows help documentation

python brokeint.py -ip 192.168.1.1/24 -iface eth0,Wi-Fi   => Scans devices with cidr display and gives information about devices

python brokeint.py -ip 192.168.1.1/24 --nmap  => The --nmap parameter scans using nmap and collects information about devices

python brokeint.py -M -iface Wi-Fi  => Warns the client against MITM attacks when accessing http sites

python brokeint.py --network  => Brings detailed information about networks and SSID around

python brokeint.py --networkPassword  => Shell opens and provides information about your own network with commands from the help documentation

python brokeint.py --deauth <packet_count> -a <modem(SSID)_mac> -c <target_mac> -iface Wi-Fi  => This command deauts the desired target and tries to interrupt its internet service
