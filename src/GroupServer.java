
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
	public final String groupConfig = "GroupConfig.bin";

	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}

	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}

	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin
		// account needs to be created

		String userFile = "UserList.bin";
		String tcFile = "TrustedClients.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream tcStream;
		ObjectInputStream userStream;
		ObjectInputStream groupStream;

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
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");

			// if no users exist, it's a new group server so generate key
			KeyPair kp = generateGroupKeypair();
			System.out.println(kp.getPublic());
			System.out.println(kp.getPrivate());

		} catch (IOException e) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		} catch (ClassNotFoundException e2) {
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();

		// This block listens for connections and creates threads on new connections
		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
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

	protected KeyPair generateGroupKeypair() {
		KeyPair keyPair = null;
		// Check if Group server has public/private keypair
		try {
			// Try to read the keypair from a file.
			FileInputStream fis_keys = new FileInputStream(groupConfig);
			ObjectInputStream keyPairStream = new ObjectInputStream(fis_keys);
			keyPair = (KeyPair) keyPairStream.readObject();
		} catch (FileNotFoundException e) {
			try {
				// The file doesn't exist, then there's no RSA keys for this client.
				System.out.println("Generating Client RSA keypair");
				keyPair = genKeyPair();
				// save the key pair for future use.
				ObjectOutputStream outStream = new ObjectOutputStream(new FileOutputStream(groupConfig));
				outStream.writeObject(keyPair);
			} catch (IOException e4) {
				e4.printStackTrace();
			}
		} catch (IOException e2) {
			e2.printStackTrace();
		} catch (ClassNotFoundException e3) {
			e3.printStackTrace();
		}
		return keyPair;
	}

	/*
	 * Method to generate public/private RSA keypair when client is launched
	 *
	 * @return keypair - client's public/private keypair
	 */
	private KeyPair genKeyPair() {
		KeyPair keyPair = null;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); // add security provider
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC"); // set RSA instance
			keyGen.initialize(2048); // set bit size
			keyPair = keyGen.genKeyPair(); // generate key pair
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e2) {
			e2.printStackTrace();
		}
		return keyPair;
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
			} catch (Exception e) {
				System.out.println("Autosave Interrupted");
			}
		} while (true);
	}
}
