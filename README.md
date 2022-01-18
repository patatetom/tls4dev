# certificates for development / testing


## openssl


### prerequisites

```console
mkdir /tmp/cert4dev/ && cd /tmp/cert4dev/
```

```console
cat > dev.conf <<~~~~
[ca]
default_ca=dev
[dev]
dir=.
database=.db
serial=.sn
policy=policy
[policy]
countryName=optional
stateOrProvinceName=optional
localityName=optional
organizationName=optional
organizationalUnitName=optional
commonName=supplied
emailAddress=optional
[intermediate]
basicConstraints = CA:true, pathlen:0
[server]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
~~~~
```

```console
touch .db .sn
```

```console
openssl version

OpenSSL 1.1.1m  14 Dec 2021
```


### self-signed CA Root

```console
openssl req \
  -new -newkey rsa:4096 -nodes \
  -keyout root.key.pem \
  -x509 -sha512 -out root.cert.pem \
  -days 30 -subj "/C=xx/ST=test/L=test/O=test/OU=test/CN=root"

Generating a RSA private key
........++++
.......++++
writing new private key to 'root.key.pem'
-----
```

```console
openssl x509 \
  -in root.cert.pem \
  -text -noout

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5f:c1:20:d8:0c:a2:f2:7a:55:2b:1c:16:65:3e:e5:4b:96:65:c0:56
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C = xx, ST = test, L = test, O = test, OU = test, CN = root
        Validity
            Not Before: Jan 16 19:37:00 2022 GMT
            Not After : Feb 15 19:37:00 2022 GMT
        Subject: C = xx, ST = test, L = test, O = test, OU = test, CN = root
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    …
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            …
            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: sha512WithRSAEncryption
         …
```


### intermediate certificate

```console
openssl req \
  -new -newkey rsa:4096 -nodes \
  -keyout intermediate.key.pem \
  -sha512 \
  -out intermediate.csr.pem \
  -subj "/C=xx/ST=test/L=test/O=test/OU=test/CN=intermediate"

Generating a RSA private key
................................++++
...................++++
writing new private key to 'intermediate.key.pem'
-----
```

```console
openssl req \
  -in intermediate.csr.pem \
  -text -noout

Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = xx, ST = test, L = test, O = test, OU = test, CN = intermediate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    …
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha512WithRSAEncryption
         …
```

```console
openssl ca \
  -cert root.cert.pem -keyfile root.key.pem \
  -extensions intermediate -rand_serial -days 30 -notext -md sha512 \
  -in intermediate.csr.pem \
  -outdir . -out intermediate.cert.pem \
  -config dev.conf

Using configuration from dev.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'xx'
stateOrProvinceName   :ASN.1 12:'test'
localityName          :ASN.1 12:'test'
organizationName      :ASN.1 12:'test'
organizationalUnitName:ASN.1 12:'test'
commonName            :ASN.1 12:'intermediate'
Certificate is to be certified until Feb 15 21:35:32 2022 GMT (30 days)
Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```

```console
openssl x509 \
  -in intermediate.cert.pem \
  -text -noout

Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            37:a3:81:09:2e:0b:c2:19:5b:0c:fa:28:99:d1:e6:c9:60:43:d2:ce
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C = xx, ST = test, L = test, O = test, OU = test, CN = root
        Validity
            Not Before: Jan 16 21:35:32 2022 GMT
            Not After : Feb 15 21:35:32 2022 GMT
        Subject: C = xx, ST = test, L = test, O = test, OU = test, CN = intermediate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    …
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: sha512WithRSAEncryption
         …
```

> _note that a copy of the certificate is created with the certificate serial number as name._
> _`37A381092E0BC2195B0CFA2899D1E6C96043D2CE.pem` in this example._

```console
rm intermediate.csr.pem 
```

```console
openssl verify \
  -verbose -CAfile root.cert.pem \
  intermediate.cert.pem

intermediate.cert.pem: OK
```


### server certificate

```console
openssl req \
  -new -newkey rsa:4096 -nodes \
  -keyout server.key.pem \
  -sha512 \
  -out server.csr.pem \
  -subj "/C=xx/ST=test/L=test/O=test/OU=test/CN=test.server"

Generating a RSA private key
....++++
..............................................................................++++
writing new private key to 'server.key.pem'
-----
```

```console
openssl req \
  -in server.csr.pem \
  -text -noout

Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: C = xx, ST = test, L = test, O = test, OU = test, CN = test.server
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    …
                Exponent: 65537 (0x10001)
        Attributes:
            a0:00
    Signature Algorithm: sha512WithRSAEncryption
         …
```

```console
openssl ca \
  -cert intermediate.cert.pem -keyfile intermediate.key.pem \
  -extensions server -rand_serial -days 30 -notext -md sha512 \
  -in server.csr.pem \
  -outdir . -out server.cert.pem \
  -config dev.conf

Using configuration from dev.conf
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'xx'
stateOrProvinceName   :ASN.1 12:'test'
localityName          :ASN.1 12:'test'
organizationName      :ASN.1 12:'test'
organizationalUnitName:ASN.1 12:'test'
commonName            :ASN.1 12:'server.test'
Certificate is to be certified until Feb 15 22:01:41 2022 GMT (30 days)
Sign the certificate? [y/n]:y
1 out of 1 certificate requests certified, commit? [y/n]y
Write out database with 1 new entries
Data Base Updated
```

```console
openssl x509 \
  -in server.cert.pem \
  -text -noout

Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            21:4c:2d:01:07:20:6e:02:59:1b:53:ec:9e:71:3a:0e:3c:c3:46:7a
        Signature Algorithm: sha512WithRSAEncryption
        Issuer: C = xx, ST = test, L = test, O = test, OU = test, CN = intermediate
        Validity
            Not Before: Jan 16 22:01:41 2022 GMT
            Not After : Feb 15 22:01:41 2022 GMT
        Subject: C = xx, ST = test, L = test, O = test, OU = test, CN = server.test
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4096 bit)
                Modulus:
                    …
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
    Signature Algorithm: sha512WithRSAEncryption
         …
```

> _note that a copy of the certificate is created with the certificate serial number as name._
> _`214C2D0107206E02591B53EC9E713A0E3CC3467A.pem` in this example._

```console
rm server.csr.pem 
```

```console
openssl verify \
  -verbose -CAfile root.cert.pem \
  -untrusted intermediate.cert.pem server.cert.pem

server.cert.pem: OK
```


### bundle

```console
cat root.cert.pem intermediate.cert.pem server.cert.pem > bundle.pem
```



## server

```console
while :
do
	echo -e "HTTP/1.0 200 OK\nContent-Length: 0\n" |
	openssl s_server -cert server.cert.pem -key server.key.pem -accept 443
done
```



## client

> upload `bundle.pem` on the client for server certificate validation.


### curl

```console
curl --version

curl 7.81.0 (x86_64-pc-linux-gnu) libcurl/7.81.0 OpenSSL/1.1.1m zlib/1.2.11 brotli/1.0.9 zstd/1.5.1 libidn2/2.3.2 libpsl/0.21.1 (+libidn2/2.3.0) libssh2/1.10.0 nghttp2/1.46.0
Release-Date: 2022-01-05
Protocols: dict file ftp ftps gopher gophers http https imap imaps mqtt pop3 pop3s rtsp scp sftp smb smbs smtp smtps telnet tftp 
Features: alt-svc AsynchDNS brotli GSS-API HSTS HTTP2 HTTPS-proxy IDN IPv6 Kerberos Largefile libz NTLM NTLM_WB PSL SPNEGO SSL TLS-SRP UnixSockets zstd
```

```console
curl https://test.server && echo OK

curl: (60) SSL certificate problem: unable to get local issuer certificate
```

```console
curl --insecure --include https://test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```

```console
curl --cacert bundle.pem --include https://test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```


### wget

```console
wget --version

GNU Wget 1.21.2 built on linux-gnu.
-cares +digest -gpgme +https +ipv6 +iri +large-file -metalink +nls 
+ntlm +opie +psl +ssl/gnutls 
Wgetrc: 
    /etc/wgetrc (system)
Locale: 
    /usr/share/locale 
Compile: 
    gcc -DHAVE_CONFIG_H -DSYSTEM_WGETRC="/etc/wgetrc" 
    -DLOCALEDIR="/usr/share/locale" -I. -I../lib -I../lib 
    -D_FORTIFY_SOURCE=2 -I/usr/include/p11-kit-1 -DHAVE_LIBGNUTLS 
    -DNDEBUG -march=x86-64 -mtune=generic -O2 -pipe -fno-plt 
Link: 
    gcc -I/usr/include/p11-kit-1 -DHAVE_LIBGNUTLS -DNDEBUG 
    -march=x86-64 -mtune=generic -O2 -pipe -fno-plt 
    -Wl,-O1,--sort-common,--as-needed,-z,relro,-z,now -lpcre2-8 -luuid 
    -lidn2 -lnettle -lgnutls -lz -lpsl ftp-opie.o gnutls.o http-ntlm.o 
    ../lib/libgnu.a /usr/lib/libunistring.so 
```

```console
wget https://test.server && echo OK

--2022-01-18 19:46:35--  https://test.server/
SSL_INIT
Loaded CA certificate '/etc/ssl/certs/ca-certificates.crt'
Resolving test.server (test.server)... 10.0.2.15
Connecting to test.server (test.server)|10.0.2.15|:443... connected.
ERROR: The certificate of 'test.server' is not trusted.
ERROR: The certificate of 'test.server' doesn't have a known issuer.
```

```console
wget --no-check-certificate --server-response --output-document=/dev/null --quiet https://test.server && echo OK

SSL_INIT
  HTTP/1.0 200 OK
  Content-Length: 0
OK
```

```console
wget --ca-certificate=bundle.pem --server-response --output-document=/dev/null --quiet https://test.server && echo OK

SSL_INIT
  HTTP/1.0 200 OK
  Content-Length: 0
OK
```


### httpie

```console
https --version

2.6.0
```

```console
https --header test.server && echo OK

https: error: ConnectionError: HTTPSConnectionPool(host='test.server', port=443): Max retries exceeded with url: / (Caused by NewConnectionError('<urllib3.connection.HTTPSConnection object at 0x7f692dc58820>: Failed to establish a new connection: [Errno 111] Connection refused')) while doing a GET request to URL: https://test.server/
```

```console
https --verify=no --header test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```

```console
https --verify=./bundle.pem --header test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```


### system trust bundle

> system is `ArchLinux` up to date

```console
trust anchor --store bundle.pem
```

```console
trust list | egrep -B1 -A2 'label: (root|intermediate|test.server)'

    type: certificate
    label: intermediate
    trust: anchor
    category: authority
--
    type: certificate
    label: root
    trust: anchor
    category: authority
--
    type: certificate
    label: test.server
    trust: anchor
    category: other-entry
```

```console
curl --include https://test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```

```console
wget --server-response --output-document=/dev/null --quiet https://test.server && echo OK

SSL_INIT
  HTTP/1.0 200 OK
  Content-Length: 0
OK
```

```console
https --header test.server && echo OK

HTTP/1.0 200 OK
Content-Length: 0
OK
```
