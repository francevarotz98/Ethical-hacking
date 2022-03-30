from scapy.all import *

def print_pkt(pkt):
	pkt.show()
	print("*"*80)


if __name__=="__main__":
	#pkt=sniff(iface='br-37d209eea436', filter='(ether src 02:42:0a:09:00:06) or (icmp and ip dst 10.9.0.6) or (tcp and (port 23 or port http))',prn=print_pkt)
	eth=Ether(src='02:42:73:bc:11:3c') #'02:42:0a:09:00:99')
	ip=IP()
	ip.src='10.9.0.5'
	ip.dst='10.9.0.6'
	icmp=ICMP()
	send(eth/ip/icmp)

	send(ip/icmp)
