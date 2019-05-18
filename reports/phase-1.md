# Applied Cryptography and Network Security

&nbsp;

## **Group:**

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

Atomicity states that all transactions in the system whether it is modifying an access control list or editing a file will be performed as a single operation in an all-or-nothing fashion. This requirement is needed so that data will not be left in an intermediate state where the system is potentially corrupted.

** **

**Property 3:** **CONSISTENCY**

Consistency states that the file must go from one valid state to another. The file cannot compromise data integrity or leave data in an intermediate state.

** **

**Property 4:** **ISOLATION**

** **

**Property 5:** **DURABILITY**

Durability states that after a transaction successfully completes, changes to data persist and are not undone, even in the event of a system failure. If file f is shared with members of group g, and a member of group g modifies and saves the file, the new file should persist.

** **

**Property 6:** **PERFORMANCE**

Performance denotes that if user X is trying to access a file, the file should be available within a reasonable timeframe. 

** **

**Property 7:**

** **

**Property 8:**

** **

**Property 9:**

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

**Threat Model 1:** **CORRECTNESS**

Correctness states that if file f is shared with members of group g, then only members of group g should be able to read, modify, delete, or see the existence of f. Without this requirement, any user could access any file, which is contrary to the notion of group-based file sharing

** **

&nbsp;

## 3. **References**

https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.4.0/product-overview/acid.html

