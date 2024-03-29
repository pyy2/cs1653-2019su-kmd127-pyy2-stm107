# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the root directory
 - Enter 'make gs GPORT=<port>'

Note that the port number argument is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the root directory
 - Enter 'make fs FPORT=<port>'

Note that the port number argument is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Resetting the Group or File Server

To reset all files, run 'make clean'

To reset the Group Server, delete the file `UserList.bin`

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.

## Running the Client

To start the text-based Client:
 - Enter the root directory
 - Enter 'make cl'

 To start the GUI Client:
  - Enter the root directory
  - Enter 'make gui'

NOTE: ClientGuiOLD has been deprecated and removed from the source repo because it was super dumb.

## Running the System

The client will ask you if you want to run in default mode. This will connect to the GroupServer running on 127.0.0.1:8765 and the FileServer running on 127.0.0.1:4321. If these servers are running on different ips/ports, select "n" to enter in specific ip/port information for each server.

On first connection, the group client will first identify that the client's fingerprint is not present and will ask for user input to confirm it wants to allow the client to connect. Then, the client will identify that the file server's fingerprint is not present and will ask for user input to confirm.

You will then be asked to log in. If it is your first time logging in, you will also be asked to update your temporary admin-assigned password. You will then be presented with a list of options on the client. If you fail to log in, you will be prompted to login again. If you fail the login three times, your account will be locked and will require and administrator to unlock it.

After logging in, the user can complete any of the actions listed in the GroupClientInterface and the FileClientInterface.

Selection of option 16 causes the user connections to the server to disconnect and the client program to end.

## Client Functionality
 - Login: This function currently only requires a user name. It takes the username and gets a token from the group client. That token persists until the application is closed of the user clicks "Logout" (in the GUI client only!).

 - Create a User: This function creates a new user with a username. The password assigned will be considered a temporary password and must be changed on first login. If a duplicate username is entered, an error message is printed. If username or password complexity requirements are not met, an error message is printed.

 - Delete a User: This function deletes the user associated with the given username. If the user does not exist, an error message is printed.

 - Create a Group: This function requires a group name. It creates the user group and assigns ownership to the requester. If the group already exists, an error message is printed.

 - Delete a Group: This function deletes the group associated with the given group name. If the requester does not own the group, an error message is printed. If the group does not exist, an error message is printed.

 - Add User to a Group: This function adds the given user to the given group. If the requester is not the owner of the group, an error message is printed. If the group does not exist or the user does not exist, an error message is printed.

 - Remove User from a Group: This function removes the given user from the given group. If the requester is not the owner of the group, an error message is printed. If the the group or the user does not exist, an error message if printed. If the user is not a member of the group, an error message is printed.

 - List Group Members: This function lists all members of a given group. If the requester is not the owner of the group, an error message is printed. If the group does not exist, an error message is printed.

 - List Files: This function lists all files associate that the user is permitted to access based on the user's group.

 - Upload a File: This function uploads the given source file as the given destination file to the given group on the file server. If the source file or the group do not exist, an error message is printed.

 - Download a File: This function downloads the given source file as the given destination file. If the user does not have sufficient group permissions, an error message is printed. If the file or the group do not exist, an error message is printed.

 - Delete a File: This function deletes the given file is the requester is a member of the file's group. If the user does not have sufficient group permissions, an error message is printed. If the file does not exist, an error message is printed.

 - Unlock a User: This function requires an admin and locked user's username. It changes the user's locked status to false.

 - Logout: This function erases the user token and prompts the user to log in to continue.

 - Exit: This function disconnects from the group and file servers and quits the Client Driver or Client GUI.
