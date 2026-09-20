# TinySSL

New tinyssl but using libcrypto 3.x and https://github.com/MWASoftware/PascalAPI4OpenSSL/tree/main</br>

<br/>
TinySSL, aka playing with openssl library for digest, cipher and certificate matters.<br/>
<br/>
The following command line options are valid:<br/>

--cn=<string>           cn<br/>
--alt=<string>          alternate name<br/>
--ca=<string>           true|false (default: false)<br/>
--password=<string>     password<br/>
--privatekey=<string>   path to a privatekey file<br/>
--cert=<string>         path to a certificate<br/>
--algo=<string>         use list_cipher or list_digest<br/>
--key=<string>          optional, used by decrypt/encrypt<br/>
--iv=<string>           optional, used by decrypt/encrypt<br/>
--utf16=<string>        true|false (default: false)<br/>
--debug=<string>        true|false (default: false)<br/>
--filename=<string>     local filename<br/>
--s_client              will retrieve ssl information from remote host, cn=host<br/>
--verify                verify a certificate against a ca cert (use cert and filename)<br/>
--print_cert            print cert details from cert<br/>
--print_private         print cert details from privatekey<br/>
--print_request         print request details from filename<br/>
--print_sshkey          print an openssh key from filename<br/>
--dhparam               generate dhparam from filename<br/>
--rand                  Generate secure random hex<br/>
--genkey                generate rsa keys public.pem and private.pem<br/>
--hash                  hash password, using algo<br/>
--base64encode          encode password to base64<br/>
--base64decode          decode password to base64<br/>
--decrypt               crypt password (hexa), using algo and optional key<br/>
--encrypt               crypt password, using algo and optional key<br/>
--list_cipher           list all ciphers<br/>
--list_digest           list all digests<br/>
--tohexa                convert a password string to hexa<br/>
--fromhexa              convert a password hexa to string<br/>
--encrypt_pub           encrypt a file using public.pem, read from filename<br/>
--decrypt_priv          decrypt a file using private.pem, read from filename<br/>
--mkcert                make a self sign root cert, read from privatekey (option) & write to filename.crt and filename.key, useds algo=EC:EC384:EC521:ED25519:RSA (default)<br/>
--mkreq                 make a certificate service request, read from privatekey & write to filename.csr filename.key (if privatekey not specified)<br/>
--signreq               make a certificate from a csr, read from filename and cert, write to filename.crt<br/>
--set_password          read from privatekey and creates a new private key with a different password - if no password provided, will remove the existing password<br/>
--dertopem              convert a binary/der private key or cert to base 64 pem format, read from cert or privatekey, write to cert.crt or privatekey.key<br/>
--pemtoder              convert a base 64 pem format to binary/der private key or cert, read from cert or privatekey, write to cert.der or privatekey.der<br/>
--p12topem              convert a pfx to pem, read from cert, write to cert.crt and cert.key<br/>
--pemtop12              convert a pem to pfx, read from cert and privatekey, write to cert.pfx<br/>
--p7topem               convert a p7b to pem, read from cert, write to cert.crt<br/>
--pemtop7               convert a pem to p7b, read from cert, write to cert.p7b<br/>
<br/><br/>
Example : create a root ca (reusing a previous key), create a csr (reusing a previous key) and generate a certificate (that will work in latest chrome).<br/>
<br/>
rem if you want to reuse an existing key and therefore renew instead of recreate<br/>
tinySSL.exe --mkcert --debug=true --privatekey=ca.key --password=password --filename=ca.crt --ca=true<br/>
rem recreate, not renew<br/>
rem tinySSL.exe --mkcert --debug=true --filename=ca.crt --ca=true --password=password<br/>
rem renew, not recreate<br/>
tinySSL.exe --mkreq --debug=true --filename=request.csr --privatekey=request.key<br/>
rem recreate, not renew<br/>
rem tinySSL.exe --mkreq --debug=true --filename=request.csr<br/>
tinySSL.exe --signreq --debug=true --alt="DNS:*.groupe.fr" --password=password --filename=request.csr --cert=ca.crt<br/>
rem lets make a fullchain cert, if needed<br/>
copy request.crt + ca.crt fullchain.crt<br/>
rem test the cert chain<br/>
tinySSL.exe --verify --cert=ca.crt --filename=request.crt<br/>
<br/>
Example : turn a cert file (pem format) into a pfx<br/>
tinyssl --pemtop12 --cert=request.crt --privatekey=request.key<br/>
rem Back to crt<br/>
tinyssl --p12topem --cert=request.pfx</br>
</br>
Exemple to generate a public/private key pair and convert into into a open ssh key for ssh purpose:<br/>
tinySSL.exe --genkey<br/>
tinyssl.exe --print_sshkey --filename=public.pem<br/>
rem now copy your ssh pub key to your ssh server authorized_keys</br>
rem lets secure the local windows private key</br>
icacls private.pem /inheritance:r<br/>
icacls private.pem /grant:r "%USERNAME%:F"<br/>
ssh -i private.pem username@ip<br/>

