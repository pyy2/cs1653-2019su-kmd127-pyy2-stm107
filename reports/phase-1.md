# Applied Cryptography and Network Security
## Specifications/Threat Modeling

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

Durability states that after a transaction successfully completes, changes to data persist and are not undone, even in the event of a system failure. If file f is shared with members of group g, and a member of group g modifies and saves the file, the saved should persist so that other members of group g will see the modifications.

** **

**Property 6:** **TURNAROUND TIME**

Turnaround time states that the system should respond to user requests within a reasonable timeframe. Turnaround time relates to all transactions in the system. For example, if user X tries to access and edit a file, the file should take no longer than 1-2 seconds to open.

** **

**Property 7:** **AVAILABILITY**

Availability states that the system should be available to authorized users when the user needs it. Otherwise the purpose of a shared file system is less beneficial than locally storing the file.

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

[IBM ACID Transactions](https://www.ibm.com/support/knowledgecenter/en/SSGMCP_5.4.0/product-overview/acid.html)

[CS1632 SoftwareQA - Security Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture15_SecurityTesting.pdf)

[CS1632 SoftwareQA - Testing](https://github.com/laboon/CS1632_Fall2018/blob/master/lectures/CS1632_Lecture11_12_PerformanceTesting.pdf)
