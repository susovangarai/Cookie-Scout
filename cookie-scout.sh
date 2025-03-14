#!/bin/bash

mth=0
idfy="Logout\|Signout\|logoff\|signoff\|Log out\|Sign out\|log off\|sign off\|HTTP/1.0 200\|HTTP/1.1 200\|HTTP/2 200"
Fg=0

Banner(){
echo '  ____      ____   _____  '
echo ' / __"| uU /"___| |" ___| '
echo ' \___ \/ \| | u  U| |_  u '
echo '  ___) |  | |/__ \|  _|/  '
echo ' |____/>>  \____| |_|     '
echo '  )(  (__)_// \\  )(\\,-  '
echo ' (__)    (__)(__)(__)(_/  '
echo '                          '
echo '     By @Vulnxpert <3  '
echo ''
}

print_usage(){
echo "Usage: scf -r <request file> -i '<Identifier>'"
echo
echo "-r: request.txt - Only post authenticated HTTP GET request file (Copy the GET request from the Burp Suite)."
echo "-i: Identifier from post authenticated pages like username, Content-Length: 1337, email, etc"
echo "-l: File containing the list of URLs for Missing Authentication check"
echo "-m: Session Cookie Finding Methods
	0 : All Methods (Default)
        1 : Single Cookie Check 
        2 : Double Cookie Check
        3 : Triple Cookie Check
        4 : Quadruple Cookie Check"
echo
echo "Ex1: With Defaults Configuration"
echo "scf -r request.txt"
echo 
echo "Ex2: Manually Passed Identifier From Response Body And Checking Only For Dual Session Cookies"
echo "scf -r request.txt -i 'Hello Admin User' -m 2"
echo 
echo "Ex3: Manually Passed Identifier From Response Headers And Checking For All The Methods Of Finding Session Cookies" 
echo "scf -r request.txt -i 'Content-Length: 1337'"
echo
echo "Ex4: Same As Ex2 With File Containing List Of Urls For Missing Authentication Check"
echo "scf -r request.txt -i 'Hello Admin User' -m 2 -l urls.txt"
}

main_scf(){

if [[ ! -z $rf ]]; then
cookie=$(cat "$rf" | grep -i 'cookie:' | sed 's/Cookie: //g')
ur=$(sed 's/\r$//' "$rf" | grep -i 'host:' | cut -d ' ' -f 2)
ul=$(sed 's/\r$//' "$rf" | grep -i 'GET\|POST' | cut -d ' ' -f 2)
Ua=$(sed 's/\r$//' "$rf" | grep -i 'User-Agent:' | sed 's/User-Agent: //g')
sed 's/\r$//' "$rf" | awk 'NF' | tail -n +3 | grep -v -i 'cookie:\|User-Agent:' > headers.log

url="https://$ur$ul"

  a=$(echo "$cookie" | sed 's/[[:space:]]//g' | awk -F';' 'NF{print NF-1}' | sort -u | tail -1)
  b=$(( $a + 1 ))


echo -e "\n\e[32m[+] Validating The GET Request\e[0"
if curl -ksi1 $url -A "$Ua" | grep -i "$idfy" &> /dev/null; then
echo -e "\e[31m[-] [Possible] Vulnerable To Missing Authentication Or Please Change The Identifier Or Check The GET Request\e[0" && exit 1;
fi

if [[ $mth == 1 || $mth == 0 ]]
then
{
  	echo -e "\n\e[32m[+] Checking For Single Session Cookie\e[0"
  		for i in $(seq 1 $b); do

    	c=$(echo "$cookie" | cut -d ';' -f $i)

    	if curl -ksi1 $url -A "$Ua" -H "Cookie: $c" -H @headers.log | grep -i "$idfy" &> /dev/null; then
		echo -e "\e[93mSingle Main Session Cookie:\e[0m $c" && Fg=1 && MissAuth ;
    	fi
  	done
}
fi

if [[ ( $Fg == 0 && $mth == 0 ) || $mth == 2 ]]
then
	echo -e "\n\e[32m[+] Checking For Double Session Cookie\e[0"
	for i in $(seq 1 $b); do
  		for j in $(seq 1 $b); do

    	c=$(echo "$cookie" | cut -d ';' -f $i)
    	d=$(echo "$cookie" | cut -d ';' -f $j)

    	if curl -ks1 $url -A "$Ua" -H "Cookie: $c; $d" -H @headers.log -i | grep -i "$idfy" &> /dev/null; then
		echo -e "\e[93mDouble Main Session Cookie:\e[0m $c; $d" && Fg=1 && MissAuth;
    	fi
  		done
    done
fi

if [[ ( $Fg == 0 && $mth == 0 ) || $mth == 3 ]]
then
	echo -e "\n\e[32m[+] Checking For Triple Session Cookie\e[0"
	for i in $(seq 1 $b); do
  		for j in $(seq 1 $b); do
  			for k in $(seq 1 $b); do

    	c=$(echo "$cookie" | cut -d ';' -f $i)
    	d=$(echo "$cookie" | cut -d ';' -f $j)
    	e=$(echo "$cookie" | cut -d ';' -f $k)

    	if curl -ks1 $url -A "$Ua" -H "Cookie: $c; $d; $e" -H @headers.log -i | grep -i "$idfy" &> /dev/null; then
		echo -e "\e[93mTriple Main Session Cookie:\e[0m $c; $d; $e" && Fg=1 && MissAuth;
    	fi
  			done
  		done
    done
fi

if [[ ( $Fg == 0 && $mth == 0 ) || $mth == 4 ]]
then
{
	echo -e "\n\e[32m[+] Checking For Quadruple Session Cookie\e[0"
	for i in $(seq 1 $b); do
  		for j in $(seq 1 $b); do
  			for k in $(seq 1 $b); do
  				for l in $(seq 1 $b); do

    	c=$(echo "$cookie" | cut -d ';' -f $i)
    	d=$(echo "$cookie" | cut -d ';' -f $j)
    	e=$(echo "$cookie" | cut -d ';' -f $k)
    	f=$(echo "$cookie" | cut -d ';' -f $l)

    	if curl -ks1 $url -A "$Ua" -H "Cookie: $c; $d; $e; $f" -H @headers.log -i | grep -i "$idfy" &> /dev/null; then
		echo -e "\e[93mQuadruple Main Session Cookie:\e[0m $c; $d; $e; $f" && Fg=1 && MissAuth;
    	fi &
  				done
  			done
  		done
    done
   wait
}
fi
fi

MissAuth
rm -rf headers.log &> /dev/null
}

MissAuth(){
if [[ ! -z $lurl ]]; then
	echo -e "\n\e[32m[+] Checking For Missing Authentication From The List Of URLs\e[0"
	cat "$lurl" | sort -u | grep -i -v "\.js$\|\.gif$\|\.png$\|\.jpg$\|\.jpeg$\|\.css$\|\.ico$" > urls.tmp

	while IFS= read tar; do
	if curl -ksi1 "$tar" | grep -i "$idfy" &> /dev/null; then
	echo -e "\e[31m$tar\e[0";
	fi &
	done < urls.tmp
	wait
exit
fi

rm urls.tmp &> /dev/null
}

while getopts 'r:i:m:l:' flag; do
	case "$flag" in
	  r) rf="${OPTARG}" ;;
	  i) idfy="${OPTARG}" ;;
	  m) mth="${OPTARG}" ;;
	  l) lurl="${OPTARG}" ;;
	  *) print_usage
		exit 1 ;;
	esac
done

if [[ $# -gt 0 ]] ; then
	Banner
	main_scf
else
	Banner
	print_usage
fi
echo
echo -e "\e[31mHappy Hacking\e[0m"
