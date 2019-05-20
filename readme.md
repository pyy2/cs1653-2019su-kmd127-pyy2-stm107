# Applied Cryptography and Network Security

## Background

Over the course of this semester, we will experiment with and apply the security concepts that are covered in lecture by developing a group-based file sharing application that is secure against a number of different types of security threats. At a high level, our system will consist of three main components: a single group server, a collection of file servers, and some number of clients.

![Background Image](https://github.com/pyy2/cs1653-2019su-kmd127-pyy2-stm107/blob/master/reports/images/background.png)

The group server manages the users in the system and keeps track of the groups to which each user belongs. Any number of file servers can be deployed throughout the network, and will rely on the group server to provide each legitimate user with an authentication and authorization token that answers the question “Who are you, and what are you permitted to do?” Users within the system make use of a networked client application to log in to the system and manage their groups (via the group server), as well as upload, download, modify, and delete files stored in the system (via the file servers).
