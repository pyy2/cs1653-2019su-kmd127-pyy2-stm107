### Phase 3 Write-Up

#### Introduction

In order to develop a more secure file-sharing system, the underlying mechanism to verify identity will be through RSA-256 public/private keys and communication channels will be secured using symmetric key AES-128 encryption. Our model fits many of the aspects addressed in Saltzer and Schroeder's principals of design. It is an open design using public cryptography methods, with separation of privilege that requires at least two protection mechanisms between the client-group server and client-file server. Using AES-128 is normally quicker than standalone RSA for psychological acceptability. The design is simple with the least amount of mechanisms deployed for acceptable verification and validation.

Each entity in the system (i.e., each client, each file server, and the group server) all have their own RSA-256 key pairs. The group server also generates a symmetric AES key to be shared with a given client (with a different shared key for each connected client). Likewise, the client generates a shared AES key for use with the connected file server. In this way, the faster hybrid-symmetric encryption scheme can be used for the sending of actual data, like user data and files. The client and the group server use a system similar to RSA fingerprinting to verify that repeat-connectors are not compromised. HMACs are used to verify that data has not been corrupted.

#### T1: Unauthorized Token Issuance

Unauthorized token issuance can occur as the result of a few different problems, each of which will need to be addressed.

1.	User Account Creation

Stolen passwords are becoming more and more prevalent. Because passwords are reused, the username/password combination is cryptographically weak. There is also a risk of impersonation when creating an account. A username provides an instance of who the user states they are, and the password verifies the user. To strengthen this component, the admin will distribute username/passwords through a secure means out of band ie. in person, imessage (encrypted end-to-end), secure email. This is to ensure that the correct user will be entering the system. Accounts cannot be created unless the user has validly logged in given the username/password combination provided by their creator.

2.	Brute Force Protection

Passwords can be brute forced. Given enough time, user passwords can be cracked. To combat brute force in conjunction with using AES cryptography which is a quicker algorithm than Blowfish and Rivest–Shamir–Adleman (RSA), a password attempt limit will be implemented with the maximum number of tries per user set at 3. AES-256 will be used because it is a quick reliable cryptographic algorithm. Upon user account creation there will need to be a field with the number of unsuccessful login attempts. The field will range from 0-2 and once the number goes above 2, the account will lock and the system will suggest that the user contact their administrator.

3.	Token Issuance

Problems 1 and 2 are only valid if the line of communication is secure from the beginning. If there is a man-in-the-middle attack, sending the username/password over an insecure line is unsafe. To solve this problem as previous stated, account creation will need to be handled from the server side. During initialization, the group server, file server, and client will create an RSA-2048 asymmetric key pair for verification and signing. RSA-2048 is chosen because according to the National Institute for Standards and Technology (NIST), RSA-1024 will likely become cracked in the near future.

RSA generation is based on integer factorization of a large prime number. Large prime integers can be found relatively efficiently using Fermat's Primality Test, however in this instance we will be using the Bouncy Castle package org.bouncycastle.crypto.generators. By default the initialize(2048) function uses the java SecureRandom() function to generate a cryptographically strong random number. Encryption/Decryption with RSA will need to be padded to normalize the length. The keys will be stored on a config file on each machine.

** **

#### T2: Token Modification/Forgery

There are multiple steps to combat against Token Modification/Forgery. To make the fileserver more secure and convince a third party that the message is legitimate, we will use RSA signing and verification combined with either SHA256 or hash-based message authentication code (HMAC). RSA signing and verification will be done using SHA256withRSA a secure hashing algorithm to generate a hash to compare with. The importance of using a secure hashing algorithm is that it is a one-way function so that it cannot be decrypted. SHA-256 was chosen because it has the best preimage resistance in relation to speed according to NIST. To generate the RSA signature, Bouncy Castle will again be used. To generate the HMAC using SHA256 digest, it will go through 2 rounds of hashing. Once to produce an inner key and hash and again to protect against length extension attacks.

When messages are sent, the RSA signature and HMAC will be generated using the party's private key. By combining the message digest encrypted with the recipient's public key and signing the HMAC that will contain the encrypted digest, a third party can validate that the message has not been tampered with although it may be prone to snooping. Prevention of snooping attacks are described in section T4.

** **

#### T3: Unauthorized File Server

To authorize that the file server s is indeed file server s and not s', there will be a public key exchange that takes place initially between the client and file server. The file server will send their public key to the client. The user will send some challenge R along with an AES symmetric key that will be encrypted using the filesystem's public key. There will also be a signed checksum sent to verify that it is indeed the client. Once the filesystem has decrypted the challenge, the file server will broadcast R unencrypted. It is important that the file system does NOT use their private key to broadcast the message. Constantly using the private key results in patterns that develop that can be used by an adversary. The client will then add s an authorized user in their config file to denote a trusted entity.

#### T4: Information Leakage via Passive Monitoring

To prevent snooping and constant reuse of public/private keys, once verification is done with public key exchanges, a symmetric key will be generated for AES-128 use. As previously mentioned, AES is quicker than RSA for usability purposes. It is also more secure and can be renewed on every connection. AES will use a CBC method with padding and a randomly generated IV so every block will be dependent on the previous block to protect against corruption/tampering. This is also implemented with Bouncy Castle.

### Implementation

**SETUP**
1. When first starting the client, group server, and file server the group server prompts for the creation of the admin account. A public/private key will be generated by RSA for the group server, file system, and client. These keys will be stored in config files for each system.
2. The user picks a username and password with appropriate complexity (username must be alphanumeric and at least 4 characters/password must be at least 8 character, contain 1 lower case, one upper case, and one number).
3. On first login (for the admin user and all other newly created users) the user is required to change their password. The user can then reset their password at any time assuming that they can produce their username and previous password, and that their new password meets password complexity requirements.

**Client-to-Group Server**

![Client-to-Group](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/clien_to_groupserver.png)

1.	Client will send their public key to the group server which will store the client key in a config file.
2.  Group server will send back its key so that the client can verify that it is actually talking to the group server and not some other server. The group server will also generate an AES key to send that is encrypted with the client's public key as well as a signed checksum of the key to verify that the key is coming from the group server and it has not been tampered with.
3.  Client will decrypt and compute the signed checksum to verify that it is legitimate. This is the first check between the client and group server that also secures the line of communication.
4.  User will enter their username/password which will be encrypted with the AES key.
5.  Upon first login, the user will be prompted to change their password with a flag attached to the username. This does not need to be encrypted.
6.  The username/password will be sent encrypted with the AES key. The client will also send a signed HMAC of the username/password with the symmetric key to verify that it has not been tampered with. Once the group server gets the password, it will hash and store the pair in a file.
7.  The group server will generate a token and send its public key concatenated with the token encrypted with the AES key. It will also send a signed HMAC using the client's public key that contains the group server key and token. This is important for the file system to verify that the token is valid and actually sent to the correct client and has not been tampered with.
8.  Any client requests will be the concatenation of request || token || padding encrypted with the shared AES key and a signed HMAC using the AES key with the same input to verify and validate the request.
9.  Similarly, any response from the group server will be the same as in 8. The token does not need to be stored anywhere and a new token will be administered every connection.


**Client-to-File Server**
![Client-to-File](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/client_to_fileserver.png)

1.	Fileserver will send the public key to the client which will be stored in a config file on the client machine.
2.  Client will generate an AES-128 key. It will send the client's public key, the encrypted AES key along with a challenge encrypted with the file server's public key, and a signed hash of the key || challenge. verifying the checksum will be the first check to make sure that there is no tampering and the client is in fact the client.
3.  The client will verify the file server when the file server responds with the unencrypted challenge. Now both parties have the symmetric key as well as each other's public key with minimal verification. This will occur every connection so that the symmetric key is refreshed.
4. Client will send the group server's public key concatenated with the token encrypted with the newly generated AES key. It will send the signed HMAC received from the group server when the token was granted. The file server will decrypt the message then compute the HMAC of the group server's public key and token with the client's public key then verify that the signature is authentic. This is where check 2 will come in. For the HMAC to be valid, the client's public key needs to be correct (not an impersonator), the signature needs to be validate (actually from the group server), and the message can't be tampered with.
5. The file server will respond with the data || token encrypted with the AES key and a signed HMAC every time and the client will need to provide the same but with a request.

## Phase 3 Division of Labor

Each part of the encryption system was fiddled with by each member of the team. Specifically:

 - Karyn Drombosky (kmd127) worked mostly on the encryption on the group server side for messages/responses, as well as the initial implementations for the HMAC and Signing for messages sent between client and group server. She also worked on the bonus and bringing the Client GUI up to date.

 - Paul Yu did the work of generating the RSA and shared keys and the initial handshakes, as well as abstracting the crypto work into it's own class and message/response encryption on the file server side. He also created the diagrams and the bulk of the report documentation.

 - Sean Mizerski created the infrastructure for saving the configs for keys and public keys. He also created the TrustedClient and TrustedFServer classes and investigated/implemented the use of "RSA-like fingerprinting" for verification of file servers and clients on second+ connections.

 - All three members proofread/verified documentation and tested the application.
