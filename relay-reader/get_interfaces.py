#!/usr/bin/env python

import netifaces as ni
import os
# pip install netifaces

for n in ni.interfaces():
    if ni.AF_LINK in ni.ifaddresses(n) and ni.AF_INET in ni.ifaddresses(n):
        print n, '\t', ni.ifaddresses(n)[ni.AF_LINK][0]['addr'], '\t', ni.ifaddresses(n)[ni.AF_INET][0]['addr']
        #XXX. Need all interfaces.
        if n == 'ens33':
          if os.path.exists("/data/if.info"):
            os.remove("/data/if.info");
          file = open("/data/if.info","w")
          file.write(n + '|' +  ni.ifaddresses(n)[ni.AF_LINK][0]['addr'] + '|' + ni.ifaddresses(n)[ni.AF_INET][0]['addr'])
          file.close()
