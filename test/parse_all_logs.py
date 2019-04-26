#!/usr/bin/python                                                                
                                                                                 
import os, sys                                                                   
import subprocess                                                                
import psycopg2                                                                  
import os.path                                                                   
from os import listdir
from os.path import isfile, join
                                                                                 
def get_immediate_subdirectories(a_dir):                                         
  return [name for name in os.listdir(a_dir)                                     
  if os.path.isdir(os.path.join(a_dir, name))]                                   

def get_all_files(a_dir):
  onlyfiles = [f for f in listdir(a_dir) if isfile(join(a_dir, f))]
  return onlyfiles
                                                                                 
def parse_klog(klog, replay_dir):
  with open("parsed."+klog,"w+") as out:
  	p = subprocess.Popen(['/home/darpa/theia-ki-target-agent/test/parseklog',replay_dir+'/'+klog], stdout=out, stderr=out)

def parse_ulog(ulog, replay_dir):
  with open("parsed."+ulog,"w+") as out:
  	p = subprocess.Popen(['/home/darpa/theia-ki-target-agent/test/parseulog',replay_dir+'/'+ulog], stdout=out, stderr=out)

replay_dir = sys.argv[1]
print replay_dir
for log in get_all_files(replay_dir): 
  print log
  if (log.startswith('klog')):
    parse_klog(log, replay_dir)
  elif (log.startswith('ulog')):
    parse_ulog(log, replay_dir)
