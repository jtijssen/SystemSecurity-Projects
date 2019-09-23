import sys
import os
import requests
import re

try:
	def findXSSVulnerability(url, payload):
		r = requests.get(url)
		if (r.status_code == 200):
			xss_data = {}
			for field in re.findall('name="(.*?)"', r.text):
				xss_data[field] = payload
			resp = requests.post(url = url, data = xss_data)
			if payload in resp.text:
				return(resp.text)
			else:
				return(None)
		else:
			print("Couldn't connect to page. Status code:", r.status_code)
			exit(1)

	print("====== Welcome to: Fuzzer ======")
	print("Please type 'x' if you want to use a simple test to see if a page has XSS vulnerabilities.")
	print("Type 'f' to path to specific files to use to test for XSS vulnerabilities.")
	choice = input("Use ctrl+D at any point to quit.\n")

	if (choice == 'x'):
		xss_url = input("What is the URL of the webpage you want to text for XSS vulnerabilities?\n")
		vuln = findXSSVulnerability(xss_url, "<script>alert('XSS!')</script>")
		if(vuln):
			print('XSS vulnerability found! (The page returned a payload script in its reponse)')
			user_r = input("Would you like to see the response text? (y/n)")
			if(user_r == 'y'):
				print(vuln)
		else:
			print("Couldn't find XSS vulnerabilities :(")

	if (choice == 'f'):
		found_bool = False
		xss_path = input("What is the filepath to the files you want to load in? (All text files in that directory will be loaded)\n")
		xss_url = input("What is the URL of the webpage you want to text for XSS vulnerabilities?\n")
		all_files = os.listdir(xss_path)
		print("Would like the payload of succesfull XSS attempts to be printed to the terminal? (y/n)")
		user_c = input("Warning! If yes, this might be a lot of text and will slow down the program. You can use Ctrl+C to quit during the printing.\n")
		for j in all_files:
			with open(xss_path + '/' + j) as f:
				lines = f.readlines()
				for s in lines:
					vuln = findXSSVulnerability(xss_url, s)
					if vuln:
						if(user_c == 'y'):
							print('Reflected content of payload:')
							print(s)
						found_bool = True
				if(found_bool):
					print('At least one XSS vulnerability found! They were found using file:', j)
				else:
					print("No XSS vulnerabilities found :(")
		print("Finished looking for vulnerabilities!")
except:
	print("Program cancelled")



