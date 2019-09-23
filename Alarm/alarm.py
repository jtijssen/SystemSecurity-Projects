#!/usr/bin/python3

from scapy.all import *
from scapy_http import http
import pcapy
import argparse

total_alerts = 0
usernames = []
passwords = []

def packetcallback(packet):
  global total_alerts
  global usernames
  global passwords
  #print(packet.summary())
  try:
    if packet[TCP].dport == 80:
      #print("HTTP (web) traffic detected!")
      req = packet.getlayer('HTTP Request')
      protocol = "HTTP"
      if req:
        auth = req.Authorization
        if auth and auth.startswith(b'Basic '):
          uname, passw = base64_bytes(auth.split(None, 1)[1]).split(b':', 1)
          total_alerts += 1
          print("ALERT #%d: Usernames and passwords sent in-the-clear (%s) username: %r, password: %r" % (total_alerts, protocol, uname.decode(), passw.decode()))
    if packet[TCP].flags:
      protocol = "TCP"
      if packet[TCP].flags == "F":
        total_alerts += 1
        incident = "FIN scan"
        addr = packet.getlayer(IP).src
        print("ALERT #%d: %s is detected from %s (%s)" %(total_alerts, incident, addr, protocol))
      if packet[TCP].flags == "FPU":
        total_alerts += 1
        incident = "XMAS scan"
        addr = packet.getlayer(IP).src
        print("ALERT #%d: %s is detected from %s (%s)" %(total_alerts, incident, addr, protocol))
      if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 21 or packet[TCP].sport == 21:
          protocol ="FTP"
          data = packet[Raw].load
          if 'USER' in data:
            usernames.append(data.split('USER')[1].strip())
            total_alerts += 1
          if 'PASS' in data:
            passwords.append(data.split('PASS')[1].strip())
          if 'USER' in data or 'PASS' in data:
            print("ALERT #%d: Usernames and passwords sent in-the-clear (%s) username: %r, password: %r" % (total_alerts, protocol, usernames[-1], passwords[-1]))
    else: 
      addr = packet.getlayer(IP).src
      total_alerts += 1
      print("ALERT #%d: NULL Scan is detected from %s (TCP)" %(total_alerts, addr))
  except:
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")