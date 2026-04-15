#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo -e "\n\t[!] This script must be run as root or using sudo\n"
    exit 1
fi

crpass="\$y\$j9T\$.GY.ksJ0zW/hNPDY/x6Cr.\$jAIlfM6onx5hgpJI91Gqr4j5Xf9PBrzDD5BWFNkO/CB"
ntfpass="\$y\$j9T\$Z0Jl8ZgFSeaW3DPtMLvu50\$wC85so4mjqX/tNiD2Pfv8XHwgEeVC65jiCuZ34aTd41"
dradpass="\$y\$j9T\$TZYZ3bmCQUOf2UaONGquW/\$Jl1UbglxCvi496v5.aqbPpmScDAFioH/tRPor3eKvM1"
otherpass="\$y\$j9T\$0dK0cmlZpi8hro9ZpMNY0/\$a95bihS3AnT1M9Z6i1f7i8MYUmwBe.BBOfxELCO3929"

notouch=("GREYTEAM" "GRAYTEAM" "SQL_APACHE_GREYTEAM" "SQL_APACHE_GRAYTEAM" "SCORER_GREYTEAM" "SCORER_GRAYTEAM" "GREY_ADMIN" "GRAY_ADMIN" "SCP073" "SCP343" "Grey Team" "Gray Team" "cyberrange" "ntf" "DR_ADMIN" "sshd" "root" "daemon" "bin" "sys" "sync" "games" "man" "lp" "mail" "news" "uucp" "proxy" "www-data" "backup" "list" "irc" "gnats" "nobody" "systemd-network" "systemd-resolve" "messagebus" "systemd-timesync" "syslog" "_apt" "tss" "uuidd" "tcpdump" "usbmux" "dns" "wazuh" "wazuh-agent" "wazuhagent")

echo -e "\033[0;36m"
cat << 'EOF'
  ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ 
  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║
  ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
                ██████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██████╗ 
               ██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔══██╗
               ██║     ███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
               ██║     ██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
               ╚██████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
                ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
EOF
echo -e "\033[0;35m"
cat << 'EOF'
                        ╔═══════════════════════════════════╗
                        ║                 :3                ║
                        ║   These passwords were changed    ║
                        ╚═══════════════════════════════════╝
EOF
echo -e "\033[0m"

sudo sed -i "s|^cyberrange:[^:]*:|cyberrange:$crpass:|" /etc/shadow
echo -e "\t•  \033[1mcyberrange\033[0m"
sudo sed -i "s|^ntf:[^:]*:|ntf:$ntfpass:|" /etc/shadow
echo -e "\t•  \033[1mntf\033[0m"

while IFS=: read -r username _; do
    if [[ "$shell" == *"nologin"* || "$shell" == *"/bin/false"* ]]; then
        continue
    fi

    shadow_entry=$(sudo grep "^$username:" /etc/shadow)
    shadow_pass=$(echo "$shadow_entry" | cut -d: -f2)

    if [[ -z "$shadow_pass" || "$shadow_pass" == "*" || "$shadow_pass" == "!" || "$shadow_pass" == "!!" ]]; then
        continue
    fi

    if [[ ! " ${notouch[@]} " =~ " $username " ]]; then
        if [[ $username == "DR_ADMIN" ]]; then
	        sudo sed -i "s|^$username:[^:]*:|$username:$dradpass:|" /etc/shadow
        else
	        sudo sed -i "s|^$username:[^:]*:|$username:$otherpass:|" /etc/shadow
        fi
        echo -e "\t•  \033[1m$username\033[0m"
    fi
done < /etc/passwd
