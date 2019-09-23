import sys
import os
import csv 
import string
import re
try:
    import geoip2.database
except:
    print('Please ensure that geoip2 and the database "GeoLite2-Country.mmdb" is correctly installed on your computer and in the same directory as this file.')
    print('For download link/instructions, see the README.')
import ipaddress
from collections import Counter

lines=[]
reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
locations = []
with open('JAR-16-20296A.csv', 'r') as csvfile:
    readCSV = csv.reader(csvfile)
    for row in readCSV:
        lines.append(row)
for k in range(len(lines)):
    lines[k] = [line.replace("[.]", ".") for line in lines[k]]
    ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', str(lines[k]) )
    if(ip):
        try:
            u_ip = str(ip).encode("utf-8")
            u_ip = u_ip.decode().split("'")[1]
            srcIP = ipaddress.ip_network(u_ip)
            resp = reader.country(u_ip)
            c = resp.country.name
            print(ip, ", location:", c)
            locations.append(c)
        except:
            pass
reader.close
print('Found the following locations: ')
print(Counter(locations))
