### Phase 3 Write-Up

#### Introduction

In order to develop a more secure filesharing system, the underlying mechanism to secure communication channels and verification will be based on Public Key Infrastructure (PKI). Different aspects of PKI in conjunction with other cryptographic techniques such as symmetric key encryption will be used to address each of the threat models that the system will need to protect against. Under the assumption that the group server is a trusted system, the group server can reliably host a list of public keys associated for the users, group server, and file system so it will serve as a trusted third party.

#### T1: Unauthorized Token Issuance

Unauthorized token issuance can occur as the result of a few different problems, each of which will need to be addressed. 

1.	User Account Creation

Stolen passwords are becoming more and more prevalent. Because passwords are reused, the username/password combination is crytographically weak. There is also a risk of impersonation when creating an account. A username provides an instance of who the user states they are, and the password verifies the user. To strengthen this component, the admin will distribute username/passwords through a secure means ie. in person, imessage (encrypted end-to-end), secure email. This is to ensure verify that the correct user will be entering the system. All other attempts to create an account will be blocked.

2.	Brute Force Protection

Passwords can be brute forced. Given enough time, user passwords can be cracked. To combat brute force in conjunction with using AES cryptography which is a quicker algorithm than Blowfish and Rivest–Shamir–Adleman (RSA), a password attempt limit will be implemented with the maximum number of tries per user set at 3. AES-256 will be used because it is a quick reliable cryptographic algorithm. Upon user account creation there will need to be a field with the number of unsuccessful login attempts. The field will range from 0-2 and once the number goes above 2, the account will lock for 5 minutes then 10 minutes, etc.

3.	Token Issuance

Problems 1 and 2 are only valid if the line of communication is secure from the beginning. If there is a man-in-the-middle attack, sending the username/password over an unsecure line is unsafe. To solve this problem as previous stated, account creation will need to be handled from the server side. The Admin of the system will generate keys to distribute to users that create an account. Also during initialization, the group server, file server, and client will create an RSA-2048 public/private keypair for asymmetric key purposes and RSA signing/verification. RSA-2048 is chosen because according to the National Institute for Standards and Technology (NIST), RSA-1024 will likely become cracked in the near future. 

RSA generation is based on integer factorization of a large prime number. Large prime integers can be found relatively efficiently using Fermat's Primality Test, however in this instance we will be using the Bouncy Castle package org.bouncycastle.crypto.generators.RSAKeyPairGenerator with the following code snippet:

    ** KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); **
    ** keyGen.initialize(new SecureRandom()); **

    public key = keypair.getPublic();
    private key = keypair.getPrivate();

    to encrypt:
    final Cipher cipher = Cipher.getInstance(RSA/NONE/OAEPWithSHA256AndMGF1Padding);

The java.security.SecureRandom package is used to generate a crypgraphically strong random number. The cipher instance will need padding because the SecureRandom() function may not necessarily be 256 bits long. The keys will be stored in a config file on each machine. 

** **
<!-- According to Saltzer and Schroeder, access to a system should not be granted based on one condition. -->

#### T2: Token Modification/Forgery

There are multiple steps to combat against Token Modification/Forgery. First the underlying principles of least privilege and separation of privilege will need to be used. Using the least privilege principle, a user should only have the permission level in the system where upon they need to perform a specific task. There will only be one root/admin account in the system that is created during initialization. Using separation of privilege, a user should not be able to make their account into a root account by just having access to the system. The user should be a member of the group server as well as know the root password to modify permissions

To make the fileserver more secure and convince a third party that the message is legitimate, we will use RSA signing and verification combined with a hash-based message authenication code (HMAC). RSA signing and verification will be done with SHA-256 a secure hashing algorithm to generate a 32-byte hash that messages can be signed with. The importantance of using a secure hashing algorithm is that it is a one-way function so that it cannot be decrypted. SHA-256 was chosen because it has the best preimage resistance in relation to speed according to NIST. To generate the RSA signature, Bouncy Castle will again be used:

    ** Signature sig = Signature.getInstance("SHA256withRSA"); ** 
    ** sig.initSign(keypair.getPrivate()); // sign data **
    ** sig.update(plaintext.getBytes()); **
    ** byte[] sigBytes = sig.sign(); **

To generate the HMAC, SHA-256

When messages are sent, the RSA signature will be generated through bouncy castle using the partie's private key. 

** **

#### T3: Unauthorized File Server

#### T4: Information Leakage via Passive Monitoring

#### Implementation

**Initialization**

1.	When first starting the client, group server, and file system the admin account is automatically created. A public/private key will be generated by RSA for the group server, file system, and client. 
2.	If new users want to create an account, they would need to contact the administrator. The admin would then provide the username/password which would be securely distributed to the individual through a secure means ie. In person, secure email, imessage (automatic end-to-end encryption). 

The admin creating the user on the system will be a means of verification and validation to the server. 

3.	When the client first connects to the group server, the client sends the public key and the group server validates the client public key. The key is stored in the config file in the group server.
4.	A Diffie Hellman key exchange takes place between the group server and client to generate a symmetric key


** Client-to-Group Server **

1.	The user logins with the given username/password encrypted with the symmetric key from the Diffie-Hellman exchange.
2.	The group server decrypts the information and checks against the stored password in the group server.
3.	If it’s the first time the user is logged in, the group server responds with a change password response encrypted.
4.	The client responds with a username and HMAC password encrypted with Kab
5.	The group server replaces the password with the hash and the Boolean flag is turned to false.
6.	The group server sends back an authentication token concatenated with the group server public key, and the token hashed with the group server public key with SHA-256 signed with the group public server that is all encrypted with the symmetric key Kab

** Client-to-File Server **

7.	On the first connection, the fileserver will send the public key to the client so that the client. The client will store the fileserver public key in a configuration file.
8.	The client will send a challenge to the fileserver that is encrypted with the file server’s public key
9.	Fileserver will respond with the same challenge unencrypted 
10.	Diffie-Hellman key exchange occurs between the client and fileserver to generate shared symmetric keys
11.	From here on, only the client server will be sending requests to the fileserver as a request concatenated with a token concatenated with the group public key with the signed hash from the group server that is encrypted with the shared key so that the fileserver can verify with the group server’s public key that the authentication token is valid. 
12.	
