intercept
========

Individually arpspoofs the target box, router and DNS server if necessary. Displays all most the interesting bits of their traffic. Cleans up after itself. 

Example usage as root:
python intercept.py -u -p -d -ip 192.168.0.10

Output: 

-u, URLs visited; truncates at 150 characters and filters image urls since they spam the output 

-p, username/passwords for FTP/IMAP/POP/IRC/HTTP, POSTs made, all searches made, and incoming/outgoing email and IRC messages sent

-d, see all images they view with driftnet

-ip, target this IP address 


Running just intercept.py without -ip argument will display all the machines on the network and show how many data packets they're sending. This is highly dependant on your wireless card and your proximity to the other machines for the data packet accuracy. 


All options:

python intercept.py -h


-v, show verbose URLs which do not truncate at 150 characters like -u

-i INTERFACE, specify interface; default is first interface in `ip route`, eg: -i wlan0

-dns DOMAIN, spoof the DNS of DOMAIN. e.g. -dns facebook.com will DNS spoof every DNS request to facebook.com or subdomain.facebook.com

-n, performs a quick nmap scan of the target

-na, performs an aggressive nmap scan in the background and outputs to [victim IP address].nmap.txt


Cleans the following on Ctrl-C:

  turn off IP forwarding

  flush iptables firewall

  individually restore each machine's ARP table


To do:

Add ability to read from pcap file
