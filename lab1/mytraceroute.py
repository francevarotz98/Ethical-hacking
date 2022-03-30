from scapy.all import *

ip=IP()
ip.dst=input('IP dst:')

for ttl_count in range(1,25):
	print('*'*30+'TTL value:'+str(ttl_count)+'*'*30)
#	print('ttl_count: '+str(ttl_count))
	ip.ttl=ttl_count
	icmp=ICMP()
	ans,unans=sr(ip/icmp)
	ip_src=ans[0][1].sprintf('%IP.src%')
#	ans.summary(lambda s,r: ip_src:=r.sprintf('%IP.src%'))
	type_icmp=ans[0][1].sprintf('%ICMP.type%')	
	if(str(type_icmp)=='time-exceeded'):
		print('time_exceeded from ip: '+str(ip_src))
	elif(str(type_icmp)=='dest-unreac'):
		print("[-] dst unreachable: "+str(ip_src))
		break
	elif(str(type_icmp)=='echo-reply'):
		print('[+] FOUND with #hop:',ttl_count)
		break
	else:
		print('type_icmp '+str(type_icmp)+'from: '+str(ip_src))
