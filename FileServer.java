
/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.*;
import java.util.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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

		final String path = "./FS"+fsNum+"public.key";
		final String path2 = "./FS"+fsNum+"private.key";
		File f1 = new File(path);
		File f2 = new File(path2);

		// if key files don't exist, something went wrong on initialization, ABORT
		if (!f1.exists() && !f2.exists()) {
			System.out.println("FS key NOT found!\n Generating FS Keys");
			Crypto crypto = new Crypto();
			crypto.setSystemKP("FS"+fsNum);
			//System.exit(1);
		}

		// set keys
		if (f1.exists() && f2.exists()) {
			System.out.println("Setting FS public/private keys\n");
			fc.setPublicKey("FS"+fsNum);
			fc.setPrivateKey("FS"+fsNum);
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

		// // check if groupserver keys exist
		// final String path = "./FSpublic.key";
		// final String path2 = "./FSprivate.key";
		// File f = new File(path);
		// File f2 = new File(path2);
		// Crypto crypto = new Crypto();
		//
		// // if key files don't exist, create new ones
		// if (!f.exists() && !f2.exists()) {
		// 	System.out.println("FS key NOT found!");
		// 	crypto.setSystemKP(fileConfig);
		// }
		// // now they should exist, set public/private key
		// if (f.exists() && f2.exists()) {
		// System.out.println("FS keys found!\nSetting public/private key");
		// crypto.setPublicKey("FS");
		// crypto.setPrivateKey("FS");
		// }

		// System.out.println(crypto.RSAtoString(crypto.getPublic())); // print out
		// group public key

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
				thread = new FileThread(sock);
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