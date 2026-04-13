if [[ $EUID -ne 0 ]]; then
    echo "\t[!] This script must be run as root or using sudo"
    exit 1
fi

crpass = "\$y\$j9T\$Q3jvzVaO/Ptc3GjddxPth0\$EEg2x3uTC4nUAiQb3UhgmZD0EosDDUEpP03o5NnVqIB"
ntfpass = ""
otherpass = "\$y\$j9T\$/8V3dgdNZrSkblazAb/S3/\$TmfmSGyqk4pavKbXLZXBJQbnixyt2mn1nssILmCxMfC"

notouch = @(
    "GREYTEAM",
    "GRAYTEAM",
    "SQL_APACHE_GREYTEAM",
    "SQL_APACHE_GRAYTEAM",
    "SCORER_GREYTEAM",
    "SCORER_GRAYTEAM",
    "GREY_ADMIN",
    "GRAY_ADMIN",
    "SCP073",
    "SCP343",
    "Grey Team",
    "Gray Team"
)

sudo sed -i "s/^cyberrange:[^:]*:/cyberrange:$crpass:/" /etc/shadow
sudo sed -i "s/^ntf:[^:]*:/ntf:$ntfpass:/" /etc/shadow

while IFS=: read -r username _; do
    if [[ ! " ${notouch[@]} " =~ " $username "]]; then
        sudo sed -i "s/^$username:[^:]*:/$username:$otherpass:/" /etc/shadow
    fi
done < /etc/passwd