# Compilation Instructions

To compile the client and server code:
 - Enter the `src/server/` directory of the repository
 - Type `javac *.java`

Initially, there will be 7 compile errors.

Once you've finished the project, there should be no warnings or errors in the compilation.

# Usage Instructions

## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java RunFileServer [port number]`

Note that the port number argument to `RunFileServer is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Resetting the Group or File Server

To reset the Group Server, delete the file `UserList.bin`

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.

## Running the Client

To start the Client:
 - Enter the directory containing `ClientDriver.class`
 - Type `java ClientDriver`

## Running the System

Begin by compiling all files:
 - Enter the `src/server/` directory of the repository
 - Type `javac *.java`

In separate terminal windows, run the FileServer and the GroupServer:
 - Enter the directory containing `RunFileServer.class`
 - Type `java RunFileServer [port number]`

 - Enter the directory containing `RunGroupServer.class`
 - Type `java RunGroupServer [port number]`

In a separate terminal window, run the client:
 - Enter the directory containing `ClientDriver.class`
 - Type `java ClientDriver`

The client will ask you if you want to run in default mode. This will connect to the GroupServer running on 127.0.0.1:8765 and the FileServer running on 127.0.0.1:4321. If these servers are running on different ips/ports, select "n" to enter in specific ip/port information for each server.

You will then be present with a list of options. Before any other task can be completed, the user must "log in" with option 1. (NOTE: For phase 2, there is no password. Just enter the username). If you fail to log in, selecting any other option will cause the client to prompt the user to sign in first.

After logging in, the user can complete any of the actions listen in the GroupClientInterface and the FileClientInterface.

Selection of option 13 causes the user connections to the server to disconnect and the client program to end.

Future enhancements will include better logging in the event of a failure on in the Thread layers for both Group and File Servers and automated testing of all methods.
