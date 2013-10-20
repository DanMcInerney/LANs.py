intercept
========

Running just intercept.py without -ip argument will arp scan the network and give you a choice of targets although I'd recommend using my wifi-monitor.py script instead since it shows data usage allowing you to pick the most active target.

Example usage:
./intercept.py -u -p -w -ip 192.168.0.10

Prints URLs visited (-u), username/passwords for FTP/IMAP/POP/IRC/HTTP, POSTs made, all searches they make (all that is -p), writes the output to the running directory in intercept.log.txt, and spoofs the target IP (-ip).

All options:

./intercept.py -h
