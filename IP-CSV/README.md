Readme

This program takes in a CSV file, cleans the IP adresses, and then runs a GeoIp2 locater on the adresses to determine from where they came.

I utilized Python3 in combination with the GeoIp2 countries library. This needs to be installed before the program can run.
To install the geoip2 module on Linux type the following into the command line:
$ pip3 install geoip2
Additionally, download the GeoIp2 countries database here:
https://dev.maxmind.com/geoip/geoip2/geolite2/
