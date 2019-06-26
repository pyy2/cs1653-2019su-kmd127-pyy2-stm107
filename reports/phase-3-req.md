## Phase 3: Overview

### Trust Model

In this phase of the project, we are going to focus on implementing a subset of the security features that will be required of our trustworthy file sharing service. Prior to describing the specific threats for which you must provide protections, we now characterize the behavior of the four classes of principals that may be present in our system:

**Group Server:** The  group  server  is  entirely  trustworthy. In this phase of the project, this means that the group server will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion,and management specified in the previous phase of the project.

**File Servers:** In this phase of the project, you may assume that properly authenticated file servers are entirely trustworthy.  In particular, you do not need to worry about a properly authenticated file server corrupting files, leaking files to unauthorized users, or stealing user tokens.

**Clients:** We will assume that clients are not trustworthy.  Specifically, clients may attempt to obtain tokens that belong to other users and/or modify the tokens issued to them by the group server to acquire additional permissions.

**Other Principals:** You should assume that all communications in the system are monitored by a passive adversary.  A passive adversary is able to watch all communication channels in an attempt to learn information, but cannot alter or disrupt any communications in the system.

** **

### Threats to Protect Against

Given the above trust model, we must now consider certain classes of threats that were not addressed in the last phase of the project. In particular, your group must develop defenses against the following classes of threats in this phase of the project:

**T1 Unauthorized Token Issuance** 

Due to the fact that clients are untrusted, we must protect against the threat of illegitimate clients requesting tokens from the groupserver. Your implementation must ensure that all clients are authenticated in a secure manner prior to issuing them tokens. That is, we want to ensure that Alice cannot request and receive Bob’s security token from the group server.

**T2 Token Modification/Forgery**

Users are expected to attempt to modify their tokens to increase their access rights, and to attempt to create forged tokens. Your implementation of the UserToken interface must be extended to allow file servers (or anyone else) to determine whether a token is in fact valid. Specifically, it must be possible for a third-party to verify that a token was in fact issued by a trusted groupserver and was not modified after issuance.

**T3  Unauthorized File Servers**

The above trust model assumes that properly authenticated file servers are guaranteed to behave as expected. In order for this guarantee to mean anything, your implementation must ensure that if a user attempts to contact some server, s, then they actually connect to s and not some other server s′. Note that any user may run a file server. As such, the group server can not be required to know about all file servers. Your mechanism for enabling users to authenticate fileservers should require communication between only the user and the file server, and possibly client-side application configuration changes. Hint:You may wish to look into how SSH allows users to authenticate servers.

**T4: Information Leakage via Passive Monitoring**

Since our trust model assumes the existence of passive attackers (e.g., nosy administrators), you must ensure that all communications between your client and server applications are hidden from outside observers. This will ensure that file contents remain private, and that tokens cannot be stolen in transit.

## Written Report: Mechanism Description

The first deliverable for this phase of the project will be a short writeup (3–5 pages) describing the cryptographic mechanisms and protocols that you will implement to address each of the identified threats. This writeup should begin with an introductory paragraph or two that broadly surveys the types of cryptographic techniques that your group has decided to use to address threats T1–T4. You should then have one section for each threat, with each section containing the following information:

    • Begin by describing the threat treated in this section. This may include describing examples of the threat being exploited by an adversary, a short discussion of why this threat is problematic and needs to be addressed, and/or diagrams showing how thethreat might manifest in your group’s current (insecure) implementation.
    
    • Next, provide a short description of the mechanism that you chose to implement to protect against this threat. For interactive protocols, it is highly recommended to include diagrams explaining the messages exchanged between participating principals.(See the lecture slides from Module 5 -  Authentication). Be sure to explain any cryptographic choices that your group makes:
    
        What types of algorithms, modes of operation, and/or key lengths did you choose? Why?  
        If shared keys are needed, how are they exchanged?
        
	• Lastly, provide a short argument addressing why your proposed mechanism sufficiently addresses this particular threat.  This argument should address the correctness of your approach, as well as its overall security.  For example, if your mechanism involves a key agreement or key exchange protocol, you should argue that both parties agree on the same key (correctness) and that no other party can figure out the key (security).
    
After completing one section for each threat, conclude with a paragraph or two discussing the interplay between your proposed mechanisms, and commenting on the design process that your group followed, including any extra credit that you did.  Did you discuss other ideas that didn’t pan out before settling on the above-documented approach?  Did you end up designing a really interesting protocol suite that addresses multiple threats at once?  Use this space to show off your hard work!

### Implementation Requirements

In order to properly address the Unauthorized Token Issuance threat (T1) described above,you will need to modify the getToken method described in GroupClientInterface.java. Since every group may choose to address this threat in a different way, we will not specify a new method signature — feel free to modify this method however is needed.  We strongly recommend  that  you  leverage  the  expertise  developed  in  Homework  HW1  and  use  theBouncyCastle cryptography API to incorporate any cryptographic functionality that youmay  need.

**Extra Credit:** As in the last phase of the project, you again have the opportunity to earn up to 5% extra credit.  Should you happen to complete the required portions of the project early, consider adding  in  extra  functionality  in  exchange  for  a  few  extra  points  (and  a  more  interesting project).  Any extra features that you add may qualify, so brainstorm as a group and see what  you  come  up  with!   If  you  opt  to  do  any  extra  credit,  be  sure  to  include  a  brief description of it in the discussion section of your writeup.
