
/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.NoSuchFileException;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public TrustedClients tcList;
	public GroupSeeds gsList;
	public GroupHashedKeys ghkList;
	public final String groupConfig = "GS";
	public PublicKey pk;

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin
		// account needs to be created
		pk = null;

		String userFile = "UserList.bin";
		String tcFile = "TrustedClients.bin";
		String gsFile = "GroupSeeds.bin";
		String ghkFile = "GroupHashedKeys.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream tcStream;
		ObjectInputStream userStream;
		ObjectInputStream gsStream;
		ObjectInputStream ghkStream;

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));

		// Open the trusted clients list
		try {
			FileInputStream fis_tc = new FileInputStream(tcFile);
			tcStream = new ObjectInputStream(fis_tc);
			tcList = (TrustedClients) tcStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("No Trusted Clients found!");
			System.out.println("Instantiating Trusted Clients list...");
			tcList = new TrustedClients();
		} catch (Exception e) {
			System.out.println("Unable to load list of trusted clients.");
			System.out.println("Exception: " + e);
		}

		// Open group seed file to get per group key info
		try {
			FileInputStream gsis = new FileInputStream(gsFile);
			gsStream = new ObjectInputStream(gsis);
			gsList = (GroupSeeds) gsStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("Group Seeds File Does Not Exist. Creating Group Seeds List...");
			System.out.println("No group seeds currently exist.");
			gsList = new GroupSeeds();
		} catch (Exception e) {
			System.out.println("Unable to load list of group seeds.");
			System.out.println("Exception: " + e);
		}

		// Open per-group key info
		try {
			FileInputStream ghkis = new FileInputStream(ghkFile);
			ghkStream = new ObjectInputStream(ghkis);
			ghkList = (GroupHashedKeys) ghkStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("Group Hashed Keys File Does Not Exist. Creating Group Hashed Keys List...");
			ghkList = new GroupHashedKeys();
		} catch (Exception e) {
			System.out.println("Unable to load list of group hashed keys.");
			System.out.println("Exception: " + e);
		}

		// Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList) userStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			System.out.print("Enter your password: ");
			String password = console.next();

			// Create a new list, add current user to the ADMIN group. They now own the
			// ADMIN group.
			userList = new UserList();
			userList.addUser(username, password);
			while (!userList.checkUser(username)) {
				System.out.println("Please try again.");
				System.out.print("Enter your username: ");
				username = console.next();
				System.out.print("Enter your password: ");
				password = console.next();
				userList.addUser(username, password);
			}
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

		} catch (IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch (ClassNotFoundException e2) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		// } finally {
		// 	//console.close();
		// }

		// check if groupserver keys exist
		final String path = "./keys/GSpublic.key";
		final String path2 = "./keys/GSprivate.key";
		File f = new File(path);
		File f2 = new File(path2);
		Crypto crypto = new Crypto();

		// if key files don't exist, create new ones
		if (!f.exists() && !f2.exists()) {
			System.out.println("GS key NOT found!");
			crypto.setSystemKP(groupConfig);
		}

		if (f.exists()) {
			crypto.setPublicKey("GS");
			pk = crypto.getPublic();
		}

		System.out.println("\n\nPublic Key:\n" + crypto.RSAtoString(pk));

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			System.out.println("###########################################");

			Socket sock = null;
			GroupThread thread = null;

			while (true) {
				sock = serverSock.accept();
				thread = new GroupThread(sock, this);
				thread.start();
			}
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

// This thread saves the user list
class ShutDownListener extends Thread {
	public GroupServer my_gs;

	public ShutDownListener(GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("GroupSeeds.bin"));
			outStream.writeObject(my_gs.gsList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("GroupHashedKeys.bin"));
			outStream.writeObject(my_gs.ghkList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		try {
			outStream = new ObjectOutputStream(new FileOutputStream("TrustedClients.bin"));
			outStream.writeObject(my_gs.tcList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread {
	public GroupServer my_gs;

	public AutoSave(GroupServer _gs) {
		my_gs = _gs;
	}

	public void run() {
		do {
			try {
				Thread.sleep(300000); // Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("TrustedClients.bin"));
					outStream.writeObject(my_gs.tcList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("GroupSeeds.bin"));
					outStream.writeObject(my_gs.gsList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("GroupHashedKeys.bin"));
					outStream.writeObject(my_gs.ghkList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			} catch (Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
}
