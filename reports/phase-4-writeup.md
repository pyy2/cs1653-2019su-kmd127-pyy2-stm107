#### T5: Message Reorder, Replay, or Modification

  To prevent from reorder, replay, or modification attacks, we will be using a few different protocols. First, for reorder and modification, we will be utilizing HMAC and RSA signature protocols. When a message is sent, whether it is a request from a client or a response form a server, the message will be of the following general structure:

  {req/resp||token||padding}K, [HMAC(K(c/f/g), req/resp||token||padding)]K(f/g)^-1

  That is to say, the request or response is concatenated with the token (if necessary), and padding and that entire concatenation is encrypted with the AES key that is shared between the client and the server. Then, the HMAC of the entire concatenation is calculated with the public key of the sender, and signed by the sender. The receiver can then verify that the message hasn't been rearranged or modified using the HMAC and the signature.

  To prevent replay attacks, we will also include the use of a nonce in each request/response.
  the nonce can be implemented fairly simply. When a message is constructed, a nonce is generated as an array of random bytes. This is then attached to the message as follows:

  {req/resp||token||nonce||padding}K, [HMAC(K(c/f/g), req/resp||token||nonce||padding)]K(f/g)^-1

  Thus, the random bytes are simply included in the message. When the receiver decrypts the message, they will check against a maintained list of used nonces to see if that nonce has been presented in to the receiver already. If it has, the message will be rejected. If it hasn't, the receiver will add the message nonce to the list of already used nonce's so that it cannot be used again. If an adversary were to try to replay the message, the message would be rejected because the nonce would be recognized as already used.

### T6: File Leakage

  We are to assume that the File Server will leak files to users that are not members of the groups that are approved to view them. It is, then, necessary for the system to create per-group keys for encrypting each file, and it is necessary to update those keys when the members of a group change. Regenerating and batch reencrypting each file isi extremely cumbersome, plus, it requires the group server to talk to the file servers directly, which is not possible in our system.

  Our solution to this problem is to implement a Lamport-like key generation system for generating new keys when group members leave, while still enabling users to decrypt files that were encrypted with older keys if they are permitted to access the file. When any file upload or download operations occur, the latest group key will be requested from the group server.

  Here is an Example:

   - Bob creates a group called dev.
   - The Group Server creates an AES key for group dev, we'll call it seed. The group server then calculates H^1000(seed), meaning that is hashes the seed 1000 times. The group server than stores the seed, the 1000th hash, and n = 1000 for this group.
   - When Bob wants to upload a file to the file server in group dev, the client first calls out to the group server to get the key info for this group.
     - After verifying that Bob is a member of the group, it provides the client with H^1000(seed) and n=1000 BUT NOT the seed itself.
     - Bob will encrypt the file with H^1000(seed), then concat n to the encrypted file. Bob then sends the following to be stored on the file server:
       nF||{FILE}H^1000(seed)
    - Alice joins group dev. When she wants to download the file, she also calls out to the group server to get the key info.
      - After verifying that Alice is a member of the group, it provides the client with H^1000(seed) and n=1000 BUT NOT the seed itself.
      - Alice gets the file from the File Server and extracts nF.
      - Alice computes n' = nF - nA (n from the file minus n that alice got from Group Server)
      - In this case, it is 0. Alice hashes the hashed seen 0 times, and can use that to decrypt the file.
    - Bob removes Alice from the group.
      - The group server decrements n associates with group dev and recalculates H to save H^999(seed), the seed, and n=999
    - Bob updates the file to File'.
      - Bob first reaches out to group server to get the latest group H^n(seed) and n
      - After verifying that Bob is a member of the group, it provides the client with H^999(seed) and n=999 BUT NOT the seed itself.
      - Bob will encrypt the file with H^999(seed), then concat n to the encrypted file. Bob then sends the following to be stored on the file server:
        nF||{FILE'}H^999(seed)
    - The file server LEAKS the file to Alice, who has been removed from the group.
      - Alice extracts nF from the file metadata, n=999.
      - Alice computes n' = nF - nA (the file's n and the n she had from when she was a member fo the group)
      - Alice gets n' = 999 - 1000 = -1. She cannot compute H^-1(H^1000(seed)) because A) she does not know the seed (it lives securely on the group server) and B) you can't go backwards in a hash function (preimage resistance)! Alice's evil intentions are foiled!
      - NOTE: it is an assumption in our system that, even though Alice is no longer a member of the group, if a file in that group is unchanged, Alice can still access it. This is basically the same as her saving local copies of the files while she is a group member to reference later, or remembering the contents of the file later.

### T7: Token Theft

  It is assumed that the file server will steal legitimate tokens from users and try to give them to other users. First, we need to ensure that a user cannot pass of another user's token as their own. This is fairly simple, in that we can simple verify that the requester's name matches the name in their token.

  We also need to ensure that the user cannot attempt to use the token they received from the rogue file server on another file server to login and attempt to access file information. To accomplish this, we can modify the Token object to contain information about the file server it is intended to be used for.

  When the client driver program first starts, it asks the user for a the IP and port of the group and file server that the user wants to connect to. When the user connects to the group server and asks for a session token, instead of just sending the encrypted username and password, it will also send the ip:port combination of its intended file server. This ip:port will then be stored as an attribute on the user's session token, which is hashed and signed by group server to ensure it has not been tampered with.

  Then, when a file server gives a stolen token to a user for use on another file server, when the user makes a request, the file server will check to see that the ip:port on the token match the file server's own ip:port. If it does not, the file server will terminate the connection and the token cannot be used on that file server.


### Protocol Diagrams

**Client-to-Group Server**

![Client-to-Group](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/p4-client-groups.png)

**Client-to-Group Server**

![Client-to-File](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/phase4_client_fileserver.png)

![Per-Group File Permission](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/groups_keys.png)
