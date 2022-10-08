#!/bin/bash

green='\e[92m'
red='\e[91m'
bwhite='\033[1;97m' #bold white
onred='\033[41m'  #background red
yello='\e[93m'
NC='\e[0m'        # No Color

printf ${bwhite}${green}
figlet welc0me NTF

echo "[*] starting recon"
printf ${bwhite}

while true ; do 

	echo -e "[+] Start recon :-
		[1] Default
		[2] Manual${NC}"
	read -p "->> which one? {1/2}: " fs
	case $fs in
		[1] ) printf ${NC} ;
			read -p "-> give me domain: " domain_name ;

			echo -e "${green}[*] attacking ${onred}${bwhite}$domain_name${NC}" ;

			/root/go/bin/assetfinder --subs-only $domain_name > asset-subs.txt ;
			/root/go/bin/subfinder -d $domain_name -silent > sub-subs.txt ;
			cat sub-subs.txt asset-subs.txt | sort -u > all-subs.txt  ;

			echo -e "${onred}${bwhite}-> check saved subdomain files${NC}"  ;
			echo -e "${green}[*] checking subdomains for ${yello}TakeOver${NC}" ;

			subzy --targets all-subs.txt | grep VULN > takeover.txt ; 
			echo -e "${onred}${bwhite}-> check takeover.txt${NC}${green}" ;
			cat takeover.txt | cut -d ' ' -f10 > subdomains.txt  ; break ;;

		[2] ) break ;;
		* ) continue ;;
	esac
done


while true; do
	printf ${NC}
	read -p "[+] want to use waybackurls? {Yy/Nn}: " yn
	case $yn in 
		[Yy]* ) cat subdomains.txt | /root/go/bin/waybackurls > wayback.txt ;
			echo -e "${onred}${bwhite}-> check wayback.txt${NC}${green}" ;
			
			
			break ;;
		[Nn]* ) break ;;
		* ) echo -e "${bwhite}${onred}~Yes or No~${NC}" ;;
	esac
	
	
done


while true; do
	printf ${NC}
	read -p "[+] want to test parameters? {Yy/Nn/Ff(full)}: " yn
	case $yn in 
		[Yy]* ) echo -e "${yello}}~ select below ${NC}:-${green}
		[0] xss
		[1] ssrf
		[2] ssti
		[3] idor
		[4] rce
		[5] redirect
		[6] lfi
		[7] sqli
		[8] img_travelsal
		[9] debug_logic
		[10] interesting_ext
		[11] interesting_params
		[12] interesting_subs
		[13] jsvar
		[14] all!
		[N] Noap!${NC}" 
			while true; do
				read -p "->> which one? {0/1/2../N}: " se ;
				case $se in
					[0] ) cat wayback.txt | gf xss ; continue ;;
					[1] ) cat wayback.txt | gf ssrf ; continue ;;
					[2] ) cat wayback.txt | gf ssti ; continue ;;
					[3] ) cat wayback.txt | gf idor ; continue ;;
					[4] ) cat wayback.txt | gf rce ; continue ;;
					[5] ) cat wayback.txt | gf redirect ; continue ;;
					[6] ) cat wayback.txt | gf lfi; continue ;;
					[7] ) cat wayback.txt | gf sqli; continue ;;
					[8] ) cat wayback.txt | gf img-traversal; continue ;;
					[9] ) cat wayback.txt | gf debug_logic; continue ;;
					[10]* ) cat wayback.txt | gf interestingEXT; continue ;;
					[11]* ) cat wayback.txt | gf interestingparams; continue ;;
					[12]* ) cat wayback.txt | gf interestingsubs; continue ;;
					[13]* ) cat wayback.txt | gf jsvar; continue ;;
					[14]* ) cat wayback.txt | gf xss , ssrf , ssti , idor , rce , lfi , sqli , img-traversal , debug_logic , interestingEXT , interestingparams , interestingsubs , jsvar ; continue ;; 
					[Nn]* ) break ;;
				esac 
			done ;
			break ;;
		[Nn]* ) break ;;
		[Ff]* ) cat wayback.txt | /root/go/bin/urlprobe -t 50 -c 100 | grep "=" | tee special_wayback.txt ; 
			break ;; 
		* ) echo -e "${bwhite}${onred}~Yes or No~${NC}" ;;
	esac

done ;




while true; do
	
	read -p "[+] want to test for CVEs? {Yy/Nn}: " cv
	case $cv in
		[Yy]* ) echo -e "${green}[*] testing for ${yello}CVEs${NC}" ;
			cat subdomains.txt | /root/go/bin/httprobe | sort -u > httprobeCVE.txt ;
			nuclei -l httprobeCVE.txt -t /root/.local/nuclei-templates/cves/ ; 
			break ;;
		[Nn]* ) break ;;
		* ) echo -e "${bwhite}${onred}~Yes or No~${NC}" ;;
	esac
done

while true; do
	
	read -p "[+] want to test with Nmap? {Yy/Nn}: " nm
	case $nm in
		[Yy]* ) echo -e "${yello}}~ select below ${NC}:-${green}
		[1] deep scan
		[2] fast scan${NC}" ;
			read -p "->> which one? {1/2/N}: " df
			case $df in
				[1] ) echo -e "${green}[*] testing with ${yello}Nmap${NC}${green} on deep mode${NC}" ; 
				      nmap -A -sC -sV -iL subdomains.txt | tee deep_nmap.txt ; break ;;
				      
				[2] ) echo -e "${green}[*] testing with ${yello}Nmap${NC}${green} on fast mode${NC}" ; 
				      nmap -sV --script=http-enum -iL subdomains.txt | tee fast_nmap.txt ; break ;;
				[Nn]* ) break ;;
				* ) echo -e "${bwhite}${onred}~{1/2/N}~${NC}" ; continue ;;

				
			esac ;
			break ;;
		[Nn]* ) break ;;
		* ) echo -e "${bwhite}${onred}~Yes or No~${NC}" ;;
	esac
done	


printf ${bwhite}${yello}
figlet ~Finished Tasks~









