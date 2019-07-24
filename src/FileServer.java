
/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.*;
import java.util.*;
import java.net.ServerSocket;
import java.net.Socket;

// security packages
import java.security.*;
import javax.crypto.*;

public class FileServer extends Server {

	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	public static PublicKey pub; // fs public key
	public static PrivateKey priv; // fs private key
	public static PublicKey gsKey;
	Crypto fc; // filecrypto class
	public final String fileConfig = "FS";

	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}

	public void start() {
		fc = new Crypto();
		// So 2 different servers don't use same keyfile
		Scanner kb = new Scanner(System.in);
		System.out.println("File Server #: ");
		String fsNum = Integer.toString(kb.nextInt());
		fsNum = fsNum.replaceAll("[^a-zA-Z0-9]", "");
		String flush = kb.nextLine();

		String fileConfig = "FS" + fsNum;

		final String gsPath = "./keys/" + fileConfig + "GS" + "public.key";
		final String path = "./keys/" + fileConfig + "public.key";
		final String path2 = "./keys/" + fileConfig + "private.key";
		File gs = new File(gsPath);
		File f1 = new File(path);
		File f2 = new File(path2);

		// get group key
		if (!gs.exists()) {
			System.out.println("Enter Group Server Key: ");
			String key = kb.nextLine();
			fc.saveGroupPK(fileConfig + "GS", fc.stringToPK(key));
		} else {
			fc.setPublicKey(fileConfig + "GS"); // set GS PubK
			gsKey = fc.getPublic();
			System.out.println("GS Public Key:\n" + fc.RSAtoString(gsKey));
		}

		gsKey = fc.getPublic();

		// if keys files don't exist, create new ones else set the keys
		if (!f1.exists() && !f2.exists()) {
			System.out.println("FS key NOT found!\n Generating FS Keys");
			fc.setSystemKP(fileConfig);
		}

		if (f1.exists() && f2.exists()) {
			System.out.println("Setting FS public/private keys\n");
			fc.setPublicKey(fileConfig);
			fc.setPrivateKey(fileConfig);
			pub = fc.getPublic();
			priv = fc.getPrivate();
		}

		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;

		// This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);

		// Open user file to get user list
		try {
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList) fileStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("FileList Does Not Exist. Creating FileList...");

			fileList = new FileList();

		} catch (IOException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		} catch (ClassNotFoundException e) {
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}

		File file = new File("shared_files");
		if (file.mkdir()) {
			System.out.println("Created new shared_files directory");
		} else if (file.exists()) {
			System.out.println("Found shared_files directory");
		} else {
			System.out.println("Error creating shared_files directory");
		}

		// Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();

		boolean running = true;

		try {
			final ServerSocket serverSock = new ServerSocket(port);
			System.out.printf("%s up and running\n", this.getClass().getName());
			System.out.println("###########################################");

			Socket sock = null;
			Thread thread = null;

			while (running) {
				sock = serverSock.accept();
				thread = new FileThread(sock, serverSock.getInetAddress().getHostAddress(), port);
				thread.start();
			}

			System.out.printf("%s shut down\n", this.getClass().getName());
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

// This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
	public void run() {
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try {
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread {
	public void run() {
		do {
			try {
				Thread.sleep(300000); // Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
