## Phase 4 Write-Up

### Introduction
 The final phase of our project deals with two distinct threat models. The first threat model deals with the idea that the file server could delete or modify files, or that an adversary could delete or modify files given access to the file server machine. Our objective is to mitigate the ease at which an adversary could find these files somewhat by making the folder name invisible. The primary defense, however is detection. We we will be implementing ways of detecting that files were deleted and/or modified and letting the end user who is trying to access those files know.

 ** **

### Trust Model

 In this phase of the project, we are going to focus on implementing a subset of the security features that will be required of our trustworthy file sharing service. Prior to describing the specific threats for which you must provide protections, we now characterize the behavior of the four classes of principals that may be present in our system:

 **Group Server:** The group server is entirely trustworthy. In this phase of the project, this means that the group server will only issue tokens to properly authenticated clients and will properly enforce the constraints on group creation, deletion, and management specified in previous phases of the project. The group server is not assumed to share secrets with the file servers in the system.

 **File Servers:** In this phase of the project, file servers will be assumed to be largely untrusted. In particular, file servers might leak files to unauthorized users or attempt to steal user tokens. File servers might also modify or delete files. File server are also assumed to be accessible by an adversary.

 **Clients:** We will assume that clients are not trustworthy. Specifically, clients may attempt to obtain tokens that belong to other users and/or modify the tokens issued to them by the group server to acquire additional permissions.

 **Other Principals:** You should assume that all communications in the system might be intercepted by a active attacker that can insert, reorder, replay, or modify messages.

 ** **

### Threats to Protect Against

 Given the above trust model, we must now consider certain classes of threats that were not addressed in the last phase of the project. In particular, your group must develop defenses against the following classes of threats in this phase of the project:

 **T8 File Modification and Deletion**

 Due to the fact that file servers are untrusted and assumed to be accessible by adversaries, we must protect against the threat of file deletion and file modification. In the case of modification, it is assumed that the adversary could modify an existing file stored on a file server to contain nefarious code. Our implementation must ensure that the shared_files folder is not readily visible. It must also ensure that any deletion or modification of requested files is detected when the end user tries to download said files, and that the end user is notified. In the case of modification, the end user is asked if they would like to continue downloading.

 **T9 Token Timing Attacks**

Timing attacks are a side channel attack focused on analyzing the time to run cryptographic algorithms. A key example of this is when the String.equals() method is used. Internal java implementations convert the String into a char array that returns false on the first discrepancy between the compared objects. This algorithms is not secure in a cryptographic environment. Brute force with runtime analysis would be lead to signficantly less time than a straight forward brute force approach against a constant algorithm. 

** **

### Attack Descriptions

 **T8 Attack: Adversary Runs Shell Scripts to Manipulate Files**

 Assume an adversary gains access to a file server machine, either by way of physically accessing the machine or through some remote protocol like ssh. The attack can easily locate the shared files because the name of the file folder is "shared_files." After cd'ing into this directory, though the files are encrypted, the adversary could delete or modify the files. The adversary could easily run a shell script that could navigate to the shared_files folder and delete all files. She could also create a virus, and run a shell script that replaces all of the existing files in the folder with identically named files that actually contain their malicious code. The end user would have no way of knowing that this was not their original file and, in downloading it, would actually be downloading the adversary's virus.

 To simulate this attack for deleting files, after uploading a file to the file server, from the src directory, run ./evil_delete.sh. All files in the .shared_files/ directory will be deleted. When the user them tries to download a file with an existing ShareFile record that is not found on disk, they will get a warning to contact their administrator immediately because their system is likely compromised!

 To simulate this attack for modifying files, after uploading a file to the file server, from the src directory, run ./evil_modify.sh. All files in the .shared_files/ directory will be appended with "!!!VIRUSVIRUSVIRUS!!!". Then, when an end user tries to download that file, its metadata hmac will not match the calculated hmac. The user will be presented with a prompt to determine if they still want to download.

  **T9 Attack**

As previously mentioned, the objects are converted to char arrays that return on the first inequality between the two arrays. Brute forcing the proposed algorithms will result in a longer return time as the guesses are correct. For example if the password was 'abc' and the guess was 'c' then the algorithm would immediately return. If the guess was 'a' it would take longer for the algorithm to return than 'c' and so forth until 'abc' was correctly guessed. 

Java Internal equals() method:
```
public boolean equals(Object anObject) {
    if (this == anObject) {
        return true;
    }
    if (anObject instanceof String) {
        String anotherString = (String)anObject;
        int n = value.length;
        if (n == anotherString.value.length) {
            char v1[] = value;
            char v2[] = anotherString.value;
            int i = 0;
            while (n-- != 0) {
                if (v1[i] != v2[i])
                    return false;
                i++;
            }
            return true;
        }
    }
    return false;
}
```

### Countermeasure Descriptions

 **T8 Countermeasure: Adversary Runs Shell Scripts to Manipulate Files**

The first and simplest countermeasure for somewhat obscuring the location of the shared files on the file server machine is to hide the folder that contains them. The infrastructure of the system will be changed to have the shared_files folder name appended with a '.'. This will make the folder invisible to anyone snooping around without using the -a option when listing the contents of a directory.

Secondly, we will focus our efforts on detecting that a compromise has happened and letting the end user know. When a file is uploaded, a separate data member will be created in the file metadata that contains a hash of the original uploaded file. When a file is then attempted to be downloaded, if it doesn't exist, the use will be notified that the file doesn't exist, and will be prompted to contact a system administrator if this is in error. If, when a file is prompted for download, the calculated hash of the uploaded/store file in shared_files does not match the file metadata hash, then the user will be warned that the file has been changed and will be asked if they wish to continue to download.

 **T9 Countermeasure: Timing Attack**
The solution is to use a constant time algorithm in place of the array comparison shown below.

```
    boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
```

The algorithm would return immediately if the lengths did not match. Then use a bit-wise OR comparison on the remaining array iterating through the whole length. The algorithm does give some information away about the length of the object however if the length is sufficiently long such as using an AES-128 bit key there still needs to be 2^128 attempts. 

When running a simulation attack on the methods the following times are reported:

equals:
46
58
70
bitwise:
128
142
148

The method is not infalliable however as seen in the isequal() method, the runtime increases in relation to the correct number of characters present. In the bitwise comparison, the whole string is run through atleast once resulting in an average higher time. 
