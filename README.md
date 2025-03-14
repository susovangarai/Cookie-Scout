cookie-scout Tool Made By Susovan Garai (@VulnXpert)


Installation Steps For Linux:
============================
	1. unzip cookie-scout-*.zip
	2. cd cookie-scout-*/
	3. chmod +x cookie-scout.sh


Usage: 
=======
	1. ./cookie-scout.sh --help


Example:
========
For Finding Main Session Cookie:
	1. Copy and paste the complete post authenticated GET request using Burp in the "request.txt" file. 
	2. ./cookie-scout.sh -r requests.txt

For Missing Authentication:
	1. In Burp, click on "Target" -> Site map.
	2. Right click on the domain name and select "Copy URLs in this host"
	3. Copy and paste the URLs in "mis-auth.txt" file.
	4. ./cookie-scout.sh -l mis-auth.txt

For both at same time:
	./cookie-scout.sh -r request.txt -l mis-auth.txt


Optional:
==========
	1. sudo ln -f cookie-scout.sh /usr/local/bin/cookie-scout
