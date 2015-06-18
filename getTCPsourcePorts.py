#!/usr/bin/python

from scapy.all import *
import sys


try: 
 packet=rdpcap(sys.argv[1])
except: 
 print "No file provided or cannot read file"
 sys.exit(0)

packetlen=len(packet)
resultlist=[]
gotips=[]

for i in range(0, packetlen):
 if packet[i].haslayer(DNSRR) == 1 and packet[i][DNSQR].qname == 'www.google.com.' and packet[i][DNSRR].type == 1 :
  gotips.append(packet[i][DNSRR].rdata)
 else: 
  pass


for i in range(0, packetlen):
 if packet[i].haslayer(IP) == 1 and packet[i].haslayer(TCP) == 1 and packet[i][IP].src == '10.134.12.96' and any(k == packet[i][IP].dst for k in gotips) and packet[i][TCP].dport == 80:
  resultlist.append(packet[i][TCP].sport)		
 else:
  pass

listconvset = set(resultlist)

for i in listconvset:
 print str(i)
