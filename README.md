# Sample_OpenSSL_RSA_Invocation_
RSA invocation using high-level OpenSSL APIs and multi-precision BN data structures, BIO (basic input/output)

Reference: the OpenSSL master repo on github
look up functions, all the API code in there...
OpenSSL manuals... many many (lots of deprecated funcs... lots of wrappers)
Some of the data structures are "hidden";must look up docs to find the source code.

Printout via EVM: you can see all the actual values modulus, public key exponent, private key exponent,
and other paramters.

Very useful: Linux manuals
https://linux.die.net/man/3/evp_pkey_keygen_init
https://linux.die.net/man/3/evp_sealinit

As is always best: try out with small numbers first (e.g., 512-bit modulus)
so it makes it easier to see everything and debug.

Instead of assert at every line, we would ideally have our own specific wrappers.
with error messages and error handling

https://web.stanford.edu/class/archive/cs/cs107/cs107.1218/resources/valgrind.html
run memleak test using valgrind from command line:
1) compile your file using gcc:
gcc -lcrypto main.c -o main
2) valgrind ./main

free everything you malloc.

#How to Install OpenSSL on Xcode

OS version: Darwin snovi 18.7.0 Darwin Kernel Version 18.7.0: Tue Jun 22 19:37:08 PDT 2021; root:xnu-4903.278.70~1/RELEASE_X86_64 x86_64

1. Download zip file from git master
2. Unzip
3. cd into the folder, from the command line, execute these lines:

> sudo su
> enter your password
> ./configure darwin64-x86_64-cc
> make depend
> make install

Successful installation should end with listing of manual man pages, such as these:

install doc/html/man7/provider-keyexch.html -> /usr/local/share/doc/openssl/html/man7/provider-keyexch.html
install doc/html/man7/provider-keymgmt.html -> /usr/local/share/doc/openssl/html/man7/provider-keymgmt.html
install doc/html/man7/provider-mac.html -> /usr/local/share/doc/openssl/html/man7/provider-mac.html
install doc/html/man7/provider-object.html -> /usr/local/share/doc/openssl/html/man7/provider-object.html
install doc/html/man7/provider-rand.html -> /usr/local/share/doc/openssl/html/man7/provider-rand.html
install doc/html/man7/provider-signature.html -> /usr/local/share/doc/openssl/html/man7/provider-signature.html
install doc/html/man7/provider-storemgmt.html -> /usr/local/share/doc/openssl/html/man7/provider-storemgmt.html
install doc/html/man7/provider.html -> /usr/local/share/doc/openssl/html/man7/provider.html
install doc/html/man7/proxy-certificates.html -> /usr/local/share/doc/openssl/html/man7/proxy-certificates.html
install doc/html/man7/ssl.html -> /usr/local/share/doc/openssl/html/man7/ssl.html
install doc/html/man7/x509.html -> /usr/local/share/doc/openssl/html/man7/x509.html

If this is not the case, you may need to change owner chown to folders like:
sudo chown -R $(whoami) /usr/local/share/man/man3 /usr/local/share/man/man5 /usr/local/share/man/man7
And give write permissions:
chmod u+w /usr/local/share/man/man3 /usr/local/share/man/man5 /usr/local/share/man/man7

Otherwise, Proceed to Xcode:
> click the Xcode project file 
> Build Settings
	> Select “All” and “Combined”
	> Under:   Linking > Other Linker Flags > Debug  
		> add “-lcrypto” //each is an indivudal entry
		> add "-lssl"
	> Under:  Search Paths > Header Search Paths > Debug
		> add “/usr/local/include/”   THIS IS THE PATH TO WHERE YOU HAVE openssl library files
	> Under:  Library Search Paths
		> add “/usr/local/lib/libcrypto.a”  
		> add “/usr/local/lib/libssl.a”           

