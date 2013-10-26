intercept
========

Individually arpspoofs the target box, router and DNS server if necessary. Displays all most the interesting bits of their traffic. Cleans up after itself. 

Example usage:
python intercept.py -u -p -d -w -ip 192.168.0.10

Output: 

-u, URLs visited; truncates at 150 characters and filters image urls since they spam the output 

-p, username/passwords for FTP/IMAP/POP/IRC/HTTP, POSTs made, all searches made 

-d, see all images they view with driftnet

-w, writes the output to the running directory in intercept.log.txt

-ip, target this IP address 


Running just intercept.py without -ip argument will arp scan the network and give you a choice of targets although my wifi-monitor.py script additionally shows data usage on the LAN allowing you to pick the most active target.

All options:

python intercept.py -h


-s, strip SSL from sites with SSLstrip

-v, show verbose URLs which do not truncate at 150 characters like -u

-i INTERFACE, specify interface; default is first interface in `ip route`, eg: -i wlan0

-dns DOMAIN, DNS spoofing; race condition with router, will fix eventually, eg: -dns google.com


Cleans the following on Ctrl-C:

  turn off IP forwarding

  flush iptables firewall

  individually restore each machine's ARP table


To do:
  integrate https://github.com/DanMcInerney/wifi-monitor

  change packet input from scapy to iptables' nfqueue like https://github.com/DanMcInerney/dnsspoof

  integrate this project with wifite?

  use twisted so we can use nfqueue as pkt input

  add ability to read from pcap
