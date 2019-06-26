### Assumptions:
 - The group server is entirely trustworthy. I.e., it will only provide tokens to *properly authenticated* users (we need to implement that authentication as part of this phase), and it will follow the group rules we already established in phase 2 (so we don't need to do any of that).

 - *Properly authenticated* (we need to define what that means as part of this phase) file servers are entirely trustworthy. It will not forward user tokens to anyone, leak files to adversaries, or server corrupted files.

 - Clients are the bad guys. They can try to get other peoples' tokens and modify tokens issued to them to get access to other groups.

 - All communications must be encrypted. Assume you're being watched. BUT, the adversary is passive, so they won't intercept and then re-send info (no man-in-the-middle).

 - Threat 1: No bad actors can get any tokens that don't belong to them. I.e., Evil Bob can't get Alice's token. We need password authentication that is properly protected.

 - Threat 2: Expect Evil Bob to try to forge a token and to try to modify his token to get greater access.

 - Threat 3: You must be able to make sure that when Alice connects to the file server, she is actually connected to a trusted file server. Look at ssh fingerprinting. So, Evil Bob can't set up an imposter file server that actually just records all of your info for future attacks.

 - Threat 4: You must encrypt all communications. Evil Bob is listening!

### Communication steps:

 1) A Client connects to a group server and a file server.

 2) A user logs in to the client. A GET token request is sent to the group server. The group server does some authentication and responds with a user token.

 3) The user sends various requests for user administration to the group server. Evil Bob is watching!

 4) The user sends various requests for file administration to the file server. Evil Bob is watching!

 - First, there is only one group server, so the client can assume that this group server is trustworthy (I think). Still, the group server, the file server, and the user should all exchange public keys.
  - Public keys are...public. So you don't need any special sending/sharing protocol. You can assume everyone knows them already.
  - So, the Group Server has Alice's public key. The File Server has Alice's key. Alice has the File Server and the Group Server's public keys.
 - In RSA, when you connect to a server for the first time, it asks you if you are sure that you want to trust this server, then stores your public key on that server, kind of, as a fingerprint, so that in subsequent connections, you can verify that the server that you are connecting to is ACTUALLY the server you connected to before.
  - This might be a good place for a hybrid approach. On connecting for the first time, Alice can generate some shared symmetric key (doesn't really matter how, AES, blowfish, whatever), and then encrypt it with the file server's public key and send it over. The file server and Alice both have this secret symmetric key and can check that they match on future connections. Then, if Evil Bob's server is pretending to be the trusted file server, it won't have this shared secret and Alice can reject the connection. This key can be stored as part of the client, maybe? Idk.
 - When Alice logs in, she'll need to send her username and password to the trustworthy group server. She can encrypt her password with the group server's public key. Then, only the group server will be able to decrypt it.
  - The Group server can store this password as a hash, assuming that the hash follows preimage resistance (though that doesn't really matter for passive attack in this stage).
 - When the group server sends Alice back her token, it should include an HMAC created with some secret that only the group server has (again, doesn't really matter how this is generated). Then token and HMAC should then be encrypted with Alice's public key. Only Alice will be able to decrypt it.
  - The group server should regenerate and check that HMAC EVERY TIME Alice sends a subsequent request. That is to say, the group server should be able to tell if Alice has changed her token or sent a fake token.
  - Alice doesn't have this secret. No one does but the Group Server.
  - If Alice tries to change her token to get more privileges, she won't be able to fake the HMAC.
 - When Alice sends messages back to the group server, they should be encrypted with the group server's public key. All we care about at this point is that they're not being snooped on.
  - When the group server then receives messages from Alice, it calculates the HMAC with it's super-secret secret to make sure Alice isn't trying to trick him with a fake token or a modified token.
 - When Alice sends requests to the file server, they should be encrypted with the file server's public key. Only the file server should be able to decrypt them, i.e. no snooping possible.
 - The file server should call out to the group server to verify that the token is legit based. That is to say, the file server should say "Hey group server, the user Alice sent me this token, can you calculate the HMAC and verify it for me?".
  -  This all works because we can assume that the group server is entirely trustworthy.
 - When the file server sends information back to Alice, it should encrypt it with Alice's public key. Then only Alice will be able to decrypt it.
