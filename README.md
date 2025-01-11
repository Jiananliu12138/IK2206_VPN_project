# Files for Project Assignment "NetPipe"

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `NetPipeClient.java` is a working client for the NetPipe application, without security.
- `NetPipeServer.java` is a working server for the NetPipe application, without security.
- `Arguments.java` is a simple parser for command line arguments. It is used by NetPipeClient and NetPipeServer. 
- `Forwarder.java` is a class with two threads to forward data between streams. It is used by NetPipeClient and NetPipeServer.
- `HandshakeMessage.java` is a class with methods and declarations for the message exchange between client and server during the handshake phase. Use it to implement the handshake protocol. (It is *not* used by any of other classes, since they do not support security.)
---        
# Files for HandshakeCertificate Assignment

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `HandshakeCertificate.java` is a skeleton file for your implementation. This is where you write your code!
- `HandshakeCertificateTest.java` has Junit 5 unit tests that you can use for testing. 
- `user-cert.pem` is a X.509 certificate in PEM format.
- `ca-cert.pem` is a X.509 certificate in PEM format, with the public key of the signer ("issuer") of `user-cert.pem`.

## Certificate configuration
---------------------------
1. Firstly, you need to download the openssl environment, where all certificate operations are performed
2. In this task, you will act as your own CA, so you need to create your own self signed CA certificate,     
   which contains a public key. Your self signed certificate should be signed using a private key

````
    openssl req -new -x509 -newkey rsa:2048 -keyout caprivatekey.pem -out certificate.pem -days 365

    openssl rsa -in caprivatekey.pem -pubout -out capublickkey.pem
````
The above code can be used as a reference

3.  A certificate for a regular user, which should be signed by a CA, is created in two steps.       
Assuming we have already generated the user's private key. The first step is to create a certificate signing request (CSR).      
A CSR contains the key, the information about the subject that the user would like to have in the certificate, and directives for the CA.

````
    openssl req -new -key userkey -out userkey.csr
````
First, generate a user private key and then request a certificate

4. The second step is to ask the CA (use private key) to sign the certificate. To sign a certificate,      
use the "x509" command to "openssl" and specify the files with the CSR and the CA certificate as parameters.       
In the next steps, we need to use the CA's public key to verify the certificate/

``````
    openssl x509 -req -in userkey.csr -CA CA.pem -CAkey caprivatekey.pem -set_serial 01 -out user.pem -days 365
``````
--------        
# Files for Handshake Encryption Assignment

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `HandshakeCrypto.java` is a skeleton file for your implementation. This is where you write your code!
- Two types of constructors
1. Read the public key from the certificate file
2. Generate a private key using the given byte array
- `HandshakeCryptoTest.java` has Junit 5 unit tests that you can use for testing. 
- `cert-pkcs1.pem`is a X.509 certificate in PEM format.
- `private-pkcs8.der`is the corresponding private key in PKCS#8/DER format.

## Data format issues
1. Convert the OpenSSL key file from PKCS#1/PEM format to PKCS#8/DER, which has better support in JCA/JCE.
````
openssl pkcs8 -nocrypt -topk8 -inform PEM -in private-pkcs1.pem  -outform DER -out private-pkcs8.der
````
2. According to the instructions in the link,       
it should be possible to generate a private key using the content of the pkcs8 file       
<https://stackoverflow.com/questions/20119874/how-to-load-the-private-key-from-a-der-file-into-java-private-key-object> 
--------      
# Files for SessionCipher Assignment

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `SessionCipher.java` is a skeleton file for your implementation. This is where you write your code!
- `SessionCipherTest.java` has a few Junit 5 unit tests that you can
  use for testing. 
- `plaininput.txt`is a sample plaintext file for testing.

In the SessionCipher class, I defined two global variables, one is the instance key of SessionKey and the other is the initial byte array ivbytes.

SessionCipher has two constructors
1. accepts a fixed Key and a random IV.
2. accepts a fixed key and a fixed IV.

- The purpose of doing this is to encrypt and decrypt the output and input streams, we use AES/CTR/NoPadding settings for encryption and decryption.
The Iv array and the key Key are both necessary elements for this encryption and decryption method

- So the idea is that after calling openEncryptedOutputStream, the caller can write data to the returned CipherOutputStream
and the data will then be encrypted and written to the output OutputStream.

- This can be read in conjunction with my comments in test.
----------
- # Files for SessionKey Assignment

- `README.md` This file. It is in in Markdown format. You can view it as a text file, or use a Markdown preview tool (there are plenty). 
- `SessionKey.java` is a skeleton file for your implementation. This is where you write your code!
- `SessionKeyTest.java` has a few Junit 5 unit tests that you can use for testing. 

SessionKey.java has two kinds of constructors
1. accepts an initial value for the length of the key, in which case the AES algorithm is used to generate a secretKey of the specified length.
2. accepts a byte array as input, in which case the AES algorithm is used directly on the byte array to generate the secretKey.


There are two methods
1. getSecretKey returns the secretKey directly.
2. getKeyBytes returns an array of bytes before the secretKey is generated by AES encryption.
