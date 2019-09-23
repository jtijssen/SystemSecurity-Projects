Readme:

The Fuzzer Tool:
	- This tool can be ran on a website to determine if the page has a cross-site 
	scripting vulnerability. Additionally, a folder with scripts in the form of
	.txt files can be loaded in to the program in order to run those specific 
	scripts against the designated website.
	Of course, 100% accuracy cannot be expected, as there are many different ways
	one can find and protect from a XSS vulnerability.

	The tool works in Python 3. It uses the requests library to get the HTML text
	from the designated webpage and then uses the regex library to find the fields
	that the scripts can be written into. Next, it makes a POST request to that
	webpage with the XSS script as the input for those fields. Lastly, it checks
	if the script is in the response text; if the script was succesfully inputted
	into the HTML, the XSS has worked!

All the aspects of the works have succesfully been implemented, including loading
in the fuzzing lists of Daniel Miessler and being able to test any page.
I asked questions on piazza to complete this lab. I spent around 4 hours on this
assignment. 