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

**Property 4:** **LOCATION TRANSPARENCY**

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

Filesystem hierarchy states that there will be a hierarchical system structure with directories and files at the bottom. This will allow files to move physical storage locations in memory while keeping the same name. It will follow a tree structure that separates naming hierachy from storage hierarchy.

** **

**Property 10:** **UNIQUE USER IDENTIFICATION**

Users will be identified uniquely in the user authentication system. Each user should have a unique username and uuid. This is important so that duplicate user ids cannot allow access where access should be prohibited.

** **

**Property 11:** **USER CREATION RESTRICTIONS**

Users will only be permitted to create other users of equivalent or lower permission levels. This is important because it prevents a user from creating a user with greater access and using that newly created user to gain access to parts of the system previously not permitted.

** **

**Property 12:** **LEAST PRIVILEGE**

Users are only given permission to perform actions that are necessary for their individual mandates. This prevents users from accessing parts of the system that are not necessary for their functions and could lead to data being corrupted or exposed.

** **

**Property 13:** **USER PERMISSION PROTECTION**

User permission protection states that a user will not be permitted to alter their own permission level. This is important because it preserves the previous tenet of Least Privilege and prevents users from allowing themselves to access parts of the system not intended for them.

** **

**Property 14:** **SYSTEM ADMINISTRATOR PRIVILEGE SEPARATION**

System Administrator Privilege Separation states that a system administrator role will exist in the system. This role and only this role will have the ability to change any given user's permission level. This prevents users of any other level from altering the permission level of other users and potentially violating Least Privilege.

** **

**Property 15:** **PASSWORD COMPLEXITY**

Password Complexity states that all user passwords must meet some predetermined level of complexity that is both reasonably sercure and usable. This prevents users from using easily guessable passwords or leaving passwords empty.

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

The filesystem be accessible and public once connected to the home network via LAN or WIFI. Since it is a shared family storage it is assumed there will be little to no sensitive information stored on the device. For ease of use, the device will not be encrypted or protected beyond the basic router network protections from the outernet.

**Relevant Properties:**

  * Correctness
  * Atomicity
  * Consistency
  * Durability
  * Unique Naming Scheme
  * Filesystem Hierarchy

** **

### **Threat Model 2:** **(Medium) SMALL BUSINESS NETWORK ATTACHED STORAGE**

**Scenario:**

This filesystem will be deployed within a small-to-medium sized office environment (~50-200 people). The NAS device will only be available to authenticated computers directly connected to the network via LAN. There will be one admin and a single filesystem that the company will use. The filesystem will contain sensitive documents pertaining to business operations that need to be protected or encrypted for use in the system.

**Assumptions:**


**Relevant Properties:**

  * Correctness
  * Atomicity
  * Consistency
  * Durability
  * Unique Naming Scheme
  * Filesystem Hierarchy

** **

### **Threat Model 3:** **(Large)**

**Scenario:**

**Assumptions:**

**Relevant Properties:**

&nbsp;

## 3. **References**

[ACID properties of transactions](https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.4.0/product-overview/acid.html)

[CS1632 SoftwareQA - Security Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture15_SecurityTesting.pdf)

[CS1632 SoftwareQA - Performance Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture11_12_PerformanceTesting.pdf)

[NFS: Network File System Protocol Specification](https://tools.ietf.org/html/rfc1094)
