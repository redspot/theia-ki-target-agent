#!/usr/bin/env python

import netifaces as ni
import os
# pip install netifaces

for n in ni.interfaces():
    if ni.AF_LINK in ni.ifaddresses(n) and ni.AF_INET in ni.ifaddresses(n):
        print n, '\t', ni.ifaddresses(n)[ni.AF_LINK][0]['addr'], '\t', ni.ifaddresses(n)[ni.AF_INET][0]['addr']
        #XXX. Need all interfaces.
        if n == 'eth0':
          ip_addr = ni.ifaddresses(n)[ni.AF_INET][0]['addr']
          if_path = "/data/if.info{0}".format(ip_addr[ip_addr.rfind('.'):])
          if os.path.exists(if_path):
            os.remove(if_path);
          file = open(if_path,"w")
          file.write(n + '|' +  ni.ifaddresses(n)[ni.AF_LINK][0]['addr'] + '|' + ip_addr)
          file.close()
