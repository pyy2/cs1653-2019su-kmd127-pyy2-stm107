# Applied Cryptography and Network Security

### CS1653: Phase 1


## Specifications/Threat Modeling
### **Group:**

| **Team Member** | **Email**       | **Github**  |
| --------------- |-----------------| ------------|
| Karyn Drombosky | kmd127@pitt.edu | kdrombosky  |
| Paul Yu         | pyy2@pitt.edu   | pyy2        |
| Sean Mizerski   | stm107@pitt.edu | stm107      |

&nbsp;

## 1. **Security Requirements**

**Property 1:** **CORRECTNESS**

Correctness states that if file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing

** **

**Property 2:** **ATOMICITY**

Atomicity states that all transactions in the system whether it is modifying an access control list or editing a file will be performed as a single operation in an all-or-nothing fashion. This requirement is needed so that data will not be left in an intermediate state where the system or data in the system is potentially corrupted.

** **

**Property 3:** **CONSISTENCY**

Consistency states that the file must go from one valid state to another. The file cannot compromise data integrity or leave data in an intermediate state.

** **

**Property 4:** **LOCATION INDEPENDENCE**

Location independence states that a file on a shared filesystem will not reveal the file's physical storage location. The filename will continue to denote a specific set of physical blocks

** **

**Property 5:** **DURABILITY**

Durability states that after a transaction successfully completes, changes to data persist and are not undone, even in the event of a system failure. If file f is shared with members of group g, and a member of group g modifies and saves the file, the saved should persist so that other members of group g will see the modifications even after a system crash.

** **

**Property 6:** **TURNAROUND TIME**

Turnaround time states that the system should respond to user requests within a reasonable timeframe. Turnaround time relates to all transactions in the system. For example, if user X tries to access and edit a file, the file should take no longer than 1-2 seconds to open.

** **

**Property 7:** **AVAILABILITY**

Availability states that the system should be available to authorized users when the user needs it. Otherwise the purpose of a shared file system is less beneficial than locally storing the file.

** **

**Property 8:** **UNIQUE NAMING SCHEME**

File / Directories will respectively be uniquely named in the filesystem. This is important so that duplicate names are not used for differing files or differing directories.


** **

**Property 9:** **FILESYSTEM HIERARCHY**

Filesystem hierarchy states that there will be a hierarchical system structure with directories and files at the bottom. This will allow files to move physical storage locations in memory while keeping the same name. It will follow a tree structure that separates naming hierarchy from storage hierarchy.

** **

**Property 10:** **UNIQUE USER IDENTIFICATION**

Users and groups will be identified uniquely in the user authentication system. Each user should have a unique username and uuid, and each group should have a unique group name and uuid. This is important so that duplicate user ids cannot allow access where access should be prohibited and duplicate group ids cannot allow elevated privileges to unauthorized users.

** **

**Property 11:** **USER CREATION RESTRICTIONS**

Users will only be permitted to create other users of equivalent or lower permission levels. Standard users will not be permitted to create, edit, or delete groups. This is important because it prevents a user from creating a user with greater access and using that newly created user to gain access to parts of the system previously not permitted.

** **

**Property 12:** **LEAST PRIVILEGE**

Users are only given permission to perform actions that are necessary for their individual mandates. This prevents users from accessing parts of the system that are not necessary for their functions and could lead to data being corrupted or exposed.

** **

**Property 13:** **USER PERMISSION PROTECTION**

User permission protection states that a user will not be permitted to alter their own permission level, including at the group level. This is important because it preserves the previous tenet of Least Privilege and prevents users from allowing themselves to access parts of the system not intended for them.

** **

**Property 14:** **SYSTEM ADMINISTRATOR PRIVILEGE SEPARATION**

System Administrator Privilege Separation states that a system administrator role will exist in the system. This role and only this role will have the ability to change any given user's permission level and a group's permission level. This prevents users of any other level from altering the permission level of other users and potentially violating Least Privilege.

** **

**Property 15:** **PASSWORD COMPLEXITY**

Password Complexity states that all user passwords must meet some predetermined level of complexity that is both reasonably secure and usable. This can be set on a system-wide or group based level. This prevents users from using easily guessable passwords or leaving passwords empty.

** **

**Property 16:** **USER SESSION EXPIRATION**

User Session Expiration states that a session object will be created when a user is authenticated with the user authentication server. That session object will have a reasonable time out. This prevents users from staying logged in to the system indefinitely, leaving access with their credentials vulnerable to the adversary.

** **

**Property 17:** **SYSTEM ELEMENT ANONYMITY**

System Element Anonymity states that the client will not reveal the existence of any files, users, or other system elements to anyone who could not legally access them. This can occur by using appropriately vague error messages when authentication fails. I.e., an adversary attempting to log in to the system by guessing a username would receive a 403 response without any text indicating whether the username or the password was incorrect.

** **

**Property 18:** **SECURE CONNECTION**

The client provides secure connection to the authentication server and the file server. This prevents adversarial snooping.

** **

**Property 19:** **CLIENT USABILITY**

Client Usability states that the client software interface is sufficiently user-friendly. This prevents users from looking for alternative potentially less secure methods of accessing the user authentication server and the file server.

** **

**Property 20:** **NECESSITY OF AUTHENTICATION**

Necessity of authentication states that no access is permitted to the file server without first receiving authentication from the user authentication server and creation of a session object. This is important because it prevents access of the file system by any adversary without appropriate permissions.

&nbsp;

## 2. **Threat Models**

### **Threat Model 1:** **(Small) HOME NETWORK ATTACHED STORAGE**

**Scenario:**

This filesystem will be deployed on the local NAS device within a small family home (~5 people) so that family members can share files and multimedia to free up local storage space. A variety of devices will be able to access the medium ie. mobile, desktop, laptop, etc. once connected to the network.

**Assumptions:**

The filesystem will be accessible and public once connected to the home network via LAN or WIFI. Since it is a shared family storage it is assumed there will be little to no sensitive information stored on the device. For ease of use, the device will not be encrypted or protected beyond the basic router network protections from the broader network. It is assumed that the file server is in a physically safe place to the standards of a private home.

It is assumed that the client will be available as an application on a personal computer or mobile device, but that the client cannot connect to the file server from the greater internet. It is assumed that the client will not connect to the file server unless valid user credentials are supplied and that only trustworthy endusers can supply valid user credentials. It is assumed that connections between the client application, the user authorization server, and the file server are secure.

It is assumed that the user authentication server exists on the local network and is guarded by the same physical security as the file server. This means that it cannot be accessed on the outside internet. It is also assumed that the user authentication server contains accurate username/password hashes for accurate authentication. It is assumed that all users exhibit least privilege, that users are created by a single system administrator, and users cannot be made by other users.


**Relevant Properties:**

  * Correctness: Files should not be available to everyone. Only authenticated users on the network should be able to access the files.
  * Atomicity: Transactions on the device should be done in an all or nothing fashion. ie. In the event of a system crash, if a file is in the midst of saving, the save should be undone and the changes reverted so that the file is not in a corrupted state.
  * Consistency: Files should go from one valid state to another. Similar to atomicity, consistency avoids having a file in a potentially corrupted state.
  * Durability: If files are saved, the data should persist on the device even through a system crash.
  * Unique Naming Scheme: Files / Directories should have different names. This will allow a separation of directory and file names and avoid overwriting names that are the same.
  * Filesystem Hierarchy: Directories should be at the top in a tree structure with files at the bottom level in a tree structure. 
  * Unique User Identification: This identifies each unique user. This is important because it prevents privileges from being assigned to the wrong user. 
  * User Creation Restrictions: This prevents a user from creating other users if they are not authorized to do so; this also prevents a user from creating a user of higher privilege in order to gain the additional access. 
  * User Permission Protection: This prevents the user from altering (elevating) their own level of privilege.
  * Secure Connection: This prevents the adversary from snooping.
  * Necessity of Authentication: Only users that have an authorized username and password can access the system.  
  * Least Privilege: This grants users access to only the files that they need to access. In the family scenario, mom and dad can have their own files that kids can't access.
  * System Administrator Separation of Privilege: One user is responsible for all user administration.


** **

### **Threat Model 2:** **(Medium) SMALL BUSINESS PROTECTED SUBNET**

**Scenario:**

This filesystem will be deployed within a small-to-medium sized office environment (~50-200 people). The NAS device will only be available to authenticated computers directly connected to the network via LAN. There will be a small number of admins and a single filesystem that the company will use. The filesystem will contain sensitive documents pertaining to business operations that need to be protected or encrypted for use in the system.

**Assumptions:**

The filesystem will only be accessible to systems connected to the LAN via a corporate VPN. It is assumed that, since sensitive information relating to business matters will be held on the server, that the server will be held in a reasonable physically secure location and that any necessary redundancy will also be held in a separate physically secure location. It is assumed that This system is not accessible from the outside internet. It is assumed that wires and switches are trustworthy and not compromised. It is assumed that every element accessible in the file system has some reference of minimum user privilege for read, write, and execute operations.

It is assumed that client interface can be installed on any corporate computer or mobile device, but that it cannot connect to the file system or user authentication system without being on the corporate network and signed in through the VPN. It is assumed that the client interface is usable, and that password complexity requirements are reasonable. It is assumed that the client software cannot connect to the file server without first authenticating with the user server. It is also assumed that the endusers (i.e. employees) are trustworthy and will not share their login credentials or confidential files to any unauthorized users. It is assumed that the existence of users and files will not be revealed in error messages form the client. It is finally assumed that the connections between the client, the user authentication server, and the file server are secure and trustworthy.

It is assumed that the user authentication server is also guarded by the same level of physical security and also contains secure redundancy for availability. It is also assumed that a minimum password complexity is set by the system administration. It is assumed that user's exhibit least privilege, can only be created by system admins, and cannot change their own permission levels. It is assumed that usernames and uuids are unique and that username/password hashes stored on the user authentication server are secure. It is assumed that user session expire in a reasonable amount of time with no activity (i.e. 30 minutes).

**Relevant Properties:**


  * Correctness: Files should not be available to everyone. Only authenticated users on the network should be able to access the files.
  * Atomicity: Transactions on the device should be done in an all or nothing fashion. ie. In the event of a system crash, if a file is in the midst of saving, the save should be undone and the changes reverted so that the file is not in a corrupted state.
  * Consistency: Files should go from one valid state to another. Similar to atomicity, consistency avoids having a file in a potentially corrupted state.
  * Durability: If files are saved, the data should persist on the device even through a system crash.
  * Unique Naming Scheme: Files / Directories should have different names. This will allow a separation of directory and file names and avoid overwriting names that are the same.
  * Filesystem Hierarchy: Directories should be at the top in a tree structure with files at the bottom level in a tree structure. 
  * Availability: The filesystem should be available when the business needs it for it to be useful. That means an uptime around 99%.
  * Turnaround Time: The filesystem should be responsive to user requests with a reasonable turnaround time such that the system is useable in daily activities. 
  * Unique User Identification: This is important so that each user has their own separate login info and definite privileges.
  * User Creation Restrictions: This prevents non-system admins from creating super users to access confidential information.
  * User Permission Protection: This prevents users from giving themselves elevated privileges without system admin approval.
  * Secure Connection: A secure connection prevents snooping on the network.
  * Necessity of Authentication: This is important so that only authorized users can access the system. It is also important so that a user's privilege level can be verified.
  * Least Privilege: This prevents users from accessing anything that they don't need.
  * Password Complexity: This helps, in some small part, to make brute force password hacking more difficult.
  * Client Usability: This helps to ensure that the authentication process is followed because it is usable and easy!
  * System Element Anonymity: This prevents hackers from gaining information about the existence of users and file on the system that can be used in further attacks.
  * User Session Expiration: This prevents a careless employee from compromising the system by forgetting to log out.
  * System Administrator Separation of Privilege: This ensures that only a select group of humans have the ability to make privilege changes in the system. If someone goes rogue, the set of suspects is smaller :). 



** **
## 3. **References**

[ACID properties of transactions](https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.4.0/product-overview/acid.html)

[CS1632 SoftwareQA - Security Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture15_SecurityTesting.pdf)

[CS1632 SoftwareQA - Performance Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture11_12_PerformanceTesting.pdf)

[NFS: Network File System Protocol Specification](https://tools.ietf.org/html/rfc1094)
