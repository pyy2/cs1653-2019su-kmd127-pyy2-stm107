## Phase 1: Overview

### Security Requirements

Brainstorm a list of security requirements that you feel should be respected by a group-based file sharing application like that described above. You may assume that the system will support the following types of operations:

	• Create/delete user  
	• Create/delete group  
	• Add/remove user u to/from group g  
	• Upload/overwrite file f to be shared with members of group g 
	• Download file f  
	• Delete file f

Given this extremely (and purposely) high-level description of the system’s functionality, your group should develop a list of properties that a secure group-based file sharing application must respect. For each property, come up with (i) a name for the property, (ii) a definition of what this property entails, (iii) a short description of why this property is important, and (iv) any assumptions upon which this property depends. As an example, consider the following:

> Property 1: Correctness. Correctness states that if file f is shared
> with members of group g, then only members of group g should be able
> to read, modify, delete, or see the existence of f. Without this
> requirement, any user could access any file, which is contrary to the
> notion of group-based file sharing.

The goal of this exercise is to get your group thinking about some of the challenges involved with building secure distributed systems. We neither assume that you are file sharing experts, nor that you have prior experience developing secure applications. To begin with, spend some time thinking about what would make you trust the security of such a system, and use this intuition to formulate your initial requirements. This will provide you with a starting point that can be refined by examining the features afforded by other systems and reading over relevant portions of your textbook.

## Written Report

### Section 1: Security Properties.

This section should describe the requirements that your group has identified as being relevant to the group-based file sharing sce- nario. You should aim to find at least 15–20 such requirements, that together will cover at least two different sets of reasonable system assumptions (i.e., threat models). This section should be arranged as a bulleted list of properties that may apply to a file sharing system.

### Section 2: Threat Models.

This section should describe several sets of trust assumptions that could be made regarding the players in the system. Describe several scenarios in which you expect the file sharing system to be used and describe the ways in which the various entities with access to the system will be trusted to behave. This section should be arranged as follows:

1. A paragraph describing a system model: an environment in which you envision your application being deployed.
2. A paragraph describing the trust assumptions that you would make regarding the players in the system, within this particular system model.
3. A bulleted list of relevant security properties from Section 1, each with a sentence or two discussing how it applies to this system / threat model. Note that not all of the security properties you define will necessarily be relevant to all of your threat models.
4. Repeat items 1–3 as needed for additional system / threat models.

### Section 3: References.

If any of the requirements in Section 1, or any of the system models in Section 2, were inspired by material from books, papers, articles, or existing products, your sources should be cited here.
