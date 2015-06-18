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
countedlist=[]

for i in range(0, packetlen):
 if packet[i].haslayer(DNSRR) == 1 and packet[i][DNSRR].type == 1:
  resultlist.append(packet[i][DNSQR].qname)
 else: 
  pass 

for i in [[x,resultlist.count(x)] for x in set(resultlist)]:
 countedlist.append(i)



dictionaryconv=dict(countedlist)


for key, value in dictionaryconv.iteritems():
 perc = (value*100.0) / sum(dictionaryconv.values())
 print "Hostname " + key + " #DNSQRs " +  str(value) + " Percentage " +  str(round(perc,4)) + "%" + " of 100% "

