openssl genrsa -out MITM/ca.key 4096
openssl req -new -x509 -days 1826 -key MITM/ca.key -out MITM/ca.crt
