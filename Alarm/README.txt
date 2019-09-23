README ALARM.py

- ALARM.py analyzes for the following incidents:
	- NULL Scan
	- XMAS scan
	- FIN scan
	- Usernames and passwords sent in-the-clear either through HTTP Basic Authentication or FTP
  When an incident is detected, an alert is printed to the terminal, including the protocol and ip-address.
  The tool works through pcapy and scapy. Scapy takes the flags for each individual packet to see 
  what type of scan was performed. If there were username-password combinations in the raw packet data,
  it also prints these to the terminal.

- Are the heuristics used in this assignment to determine incidents "even that good"?
	- Yes and no. While it does correctly see what scans have been used, it provides no context, 
	  making it hard to determine who and why someone scanned. Therefore, it is hard to say if something
	  is just an innocent scan, or a full on malicious actor driven incident. 
