ifconfig | grep "netmask" | awk '{if ($2 != "127.0.0.1") print $4 }'
