intercept
========

-s: Prints all searchs they make. Can get some false positives, just use in conjunction with -u so you can see the URL the search term is being pulled from
-p: Print usernames/passwords and all POSTs made
-u: Print the URL they're visiting minus .jpg, .css, .js, etc. and truncated at 150 characters
-uv: Print all URLs unfiltered
-d: Print all DNS requests they make
-dns <site.com>: Spoofs DNS for site.com. This is a race condition with the router so it's not 100% reliable
-ssl: Run sslstrip to strip off https
-ip <ip address>: Arp spoof ip address

Running just intercept.py without -ip argument will arp scan the network and give you a choice of targets then just arp spoof the target

Example:
./intercept.py -s -u -p -ip 192.168.0.10
Would print URLs visited, username/passwords entered, POSTs made, and all searches they make
