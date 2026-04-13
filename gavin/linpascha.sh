if [[ $EUID -ne 0 ]]; then
    echo "\t[!] This script must be run as root or using sudo"
    exit 1
fi

crpass = "\$y\$j9T\$SzBcDcvwBua7i6sacLAzh/\$e5xfYGZgQwV81f8lrqIaXJ6sopT/5Ie.NwO.l2f9KPC"
ntfpass = "\$y\$j9T\$Z0Jl8ZgFSeaW3DPtMLvu50\$wC85so4mjqX/tNiD2Pfv8XHwgEeVC65jiCuZ34aTd41"
dradpass = "\$y\$j9T\$TZYZ3bmCQUOf2UaONGquW/\$Jl1UbglxCvi496v5.aqbPpmScDAFioH/tRPor3eKvM1"
otherpass = "\$y\$j9T\$0dK0cmlZpi8hro9ZpMNY0/\$a95bihS3AnT1M9Z6i1f7i8MYUmwBe.BBOfxELCO3929"

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
    "Gray Team",
    "cyberrange",
    "ntf",
    "DR_ADMIN"
)

sudo sed -i "s|^cyberrange:[^:]*:|cyberrange:$crpass:|" /etc/shadow
sudo sed -i "s/^ntf:[^:]*:/ntf:$ntfpass:/" /etc/shadow

while IFS=: read -r username _; do
    if [[ ! " ${notouch[@]} " =~ " $username "]]; then
        if [[username == "DR_ADMIN" ]]; then
            sudo sed -i "s/^DR_ADMIN:[^:]*:/$username:$otherpass:/" /etc/shadow
        else
            sudo sed -i "s/^$username:[^:]*:/$username:$otherpass:/" /etc/shadow
        fi
    fi
done < /etc/passwd