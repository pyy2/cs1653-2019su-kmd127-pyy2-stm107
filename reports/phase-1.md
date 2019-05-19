# Applied Cryptography and Network Security

### CS1653: Phase 1


## Specifications/Threat Modeling
### **Group:**

| **Team Member** | **Email**       | **Github**  |
| --------------- |-----------------| ------------|
| Karyn Drombosky | kdm127@pitt.edu | kdrombosky  |
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

**Property 10:**

** **

**Property 11:**

** **

**Property 12:**

** **

**Property 13:**

** **

**Property 14:**

** **

**Property 15:**

** **

**Property 16:**

** **

**Property 17:**

** **

**Property 18:**

** **

**Property 19:**

** **

**Property 20:**

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

**Threat Model 2:** **(Medium) SMALL BUSINESS NETWORK ATTACHED STORAGE**

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

**Threat Model 3:** **(Large) **

**Scenario:**

**Assumptions:**

**Relevant Properties:**

&nbsp;

## 3. **References**

[ACID properties of transactions](https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.4.0/product-overview/acid.html)

[CS1632 SoftwareQA - Security Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture15_SecurityTesting.pdf)

[CS1632 SoftwareQA - Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture11_12_PerformanceTesting.pdf)

[NFS: Network File System Protocol Specification](https://tools.ietf.org/html/rfc1094)
