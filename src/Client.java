import java.net.Socket;
import java.net.UnknownHostException;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.SecretKey;

public abstract class Client {

	/*
	 * protected keyword is like private but subclasses have access Socket and
	 * input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	// String keyFile = "ClientKeyPair.bin";
	String tfsFile = "TrustedFServer.bin";
	TrustedFServer tfsList;
	ObjectInputStream tfsStream;

	// crypto stuff

	protected Crypto c;
	PublicKey pub; // clien'ts publickey
	PrivateKey priv; // client's private key
	SecretKey sharedKey; // symmetric AES key
	PublicKey fsPub; // fileserver public key
	SecretKey veriK;

	// accessible in FileClient thread
	static PublicKey groupK = null;
	static byte[] fsMac;
	Scanner kb;
	// expseq_g = 0;
	// expseq_f = 0;

	public boolean connect(final String server, final int port, final String type, final String clientNum) {

		kb = new Scanner(System.in);
		// init variables
		String clientConfig = "CL" + clientNum;
		fsMac = null;
		c = new Crypto();

		System.out.println("\n########### 1. INITIALIZATION ###########\n");

		// configure group public key
		final String gsPath = "./keys/" + clientConfig + "GS" + "public.key";
		File gs = new File(gsPath);

		// get group key
		if (!gs.exists()) {
			System.out.println("Enter Group Server Key: ");
			String key = kb.nextLine();
			c.saveGroupPK(clientConfig + "GS", c.stringToPK(key));
			c.setPublicKey(clientConfig + "GS"); // set GS PubK
			groupK = c.getPublic();
		}

		if (groupK == null) {
			c.setPublicKey(clientConfig + "GS"); // set GS PubK
			groupK = c.getPublic();
			System.out.println("GS Public Key Set: \n" + c.RSAtoString(groupK));
		}

		// set client key file paths
		final String path = "./keys/" + clientConfig + "public.key";
		final String path2 = "./keys/" + clientConfig + "private.key";
		File f = new File(path);
		File f2 = new File(path2);

		// if client key files don't exist, create new ones
		if (!f.exists() && !f2.exists()) {
			System.out.println("CL key NOT found!");
			c.setSystemKP(clientConfig);
		}

		if (f.exists() && f2.exists()) {
			System.out.println("CL public/private key: Set");
			c.setPublicKey(clientConfig);
			c.setPrivateKey(clientConfig);
			pub = c.getPublic();
			priv = c.getPrivate();
		}
		// System.out.println(c.RSAtoString(pub)); // print out public key base64

		// Open the trusted file servers list
		try {
			FileInputStream fis_tfs = new FileInputStream(tfsFile);
			tfsStream = new ObjectInputStream(fis_tfs);
			tfsList = (TrustedFServer) tfsStream.readObject();
		} catch (FileNotFoundException e) {
			System.out.println("No Trusted File Servers found!");
			System.out.println("Instantiating Trusted File Servers list...");
			tfsList = new TrustedFServer();
		} catch (Exception e) {
			System.out.println("Unable to load list of trusted file servers.");
			System.out.println("Exception: " + e);
		}
		System.out.println("\n########### INITIALIZATION COMPLETE ###########\n");

		// Try to create new socket connection
		try {
			sock = new Socket(server, port); // create Stream socket then connect to named host @ port #
			System.out.println("Connected to " + server + " on port " + port);
			output = new ObjectOutputStream(sock.getOutputStream()); // send output to socket
			input = new ObjectInputStream(sock.getInputStream()); // get input from socket

			// Group Server connection
			if (!type.equals("file")) {
				System.out.println("\n########### 2. ATTEMPT TO SECURE GS CONNECTION ###########\n");
				System.out.println("CL public key -> GS: Sent");
				output.writeObject(pub); // write public key to channel (not encoded)
				output.flush();

				// verify gs public key with one on file if not exit program
				PublicKey gsKeyCheck = (PublicKey) input.readObject();
				if (c.isEqual(groupK.getEncoded(), gsKeyCheck.getEncoded())) {
					System.out.println("GS Public Key -> CL: Verified");
				} else {
					System.out.println("INVALID GS KEY RECEIVED!");
					System.exit(3);
				}

				// generate new pseudo-random number and send to GS
				c.setRandom(); // generate new secure random (32 byte)
				String random = c.byteToString(c.getRandom());
				System.out.println("\nCL Random -> GS:\n" + random);
				output.writeObject(c.encrypt("RSA/ECB/PKCS1Padding", random, groupK)); // encrypt w gs private key
				output.flush();

				// read pseudo-random number from GS
				String clRand = c.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv);
				System.out.println("\nGS Random -> CL:\n" + clRand);

				byte[] ka = c.createChecksum(random + clRand); // SHA256(Ra||Rb)
				byte[] kb = c.createChecksum(clRand + random); // SHA256(Rb||Ra)
				veriK = c.makeAESKeyFromString(kb);
				c.setVeriK(veriK); // set verification key

				// decrypt with private key to get aes key
				c.setAESKey(c.byteToString(ka));
				sharedKey = c.getAESKey();
				System.out.println("\nGS Shared Key: " + sharedKey);
				System.out.println("\nGS Shared Verification Key: " + veriK);

				System.out.println("############## CONNECTION TO GS SECURE ##############\n");

			} else {
				System.out.println("\n########### 3. ATTEMPT TO SECURE FS CONNECTION ###########\n");

				c.setSysK(input.readObject()); // read fs public key not encoded
				fsPub = c.getSysK(); // set FS pub key
				System.out.println("FS Public Key -> CL: \n" + c.RSAtoString(fsPub));

				// send client's public key to client
				output.writeObject(pub);
				output.flush();
				System.out.println("\nClient public key -> FS: Sent");

				if (tfsList == null) {
					tfsList = new TrustedFServer();
				}
				if (tfsList.pubkeys != null) {
					// Check to see if ip:pubkey pair exists yet.
					if (tfsList.pubkeys.containsKey(sock.getInetAddress().toString())) {
						// If the ip is there, make sure that the pubkey matches.
						List<PublicKey> storedFSKeys = tfsList.pubkeys.get(sock.getInetAddress().toString());
						tfsList.pubkeys.get(sock.getInetAddress().toString());
						if (!storedFSKeys.contains(fsPub)) {
							Scanner in = new Scanner(System.in);
							System.out.println("Warning: stored fingerprint do not match the incoming file server key!");
							System.out.println("Continue connecting to file server? (y/n)");
							if (in.next().charAt(0) == 'y') {
								System.out.println("Adding file server's public key to trusted file servers list...");
								tfsList.addServer(sock.getInetAddress().toString(), fsPub);
							} else {
								System.out.println("Terminating connection...");
								sock.close(); // Close the socket
							}
						}
						// The keys match, it's safe to proceed
						else {
							System.out.println("File Server Fingerprint verified!");
						}
					}
					// IP does not yet exist in trusted client list. Add it.
					else {
						System.out.println("This is your first time connecting this client to the file server.");
						Scanner in = new Scanner(System.in);
						System.out.println("Warning: stored fingerprint do not match the incoming file server key!");
						System.out.println("Continue connecting to file server? (y/n)");
						if (in.next().charAt(0) == 'y') {
							System.out.println("Adding file server's public key to trusted file servers list...");
							tfsList.addServer(sock.getInetAddress().toString(), fsPub);
						} else {
							System.out.println("Terminating connection...");
							sock.close(); // Close the socket
						}
					}
				}

				// Save the Trusted File Server List
				ObjectOutputStream outStream;
				try {
					outStream = new ObjectOutputStream(new FileOutputStream(tfsFile));
					outStream.writeObject(tfsList);
				} catch (Exception e) {
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}

				// generate new random # & challenge
				c.setRandom(); // generate new secure random (32 byte)
				String random = c.byteToString(c.getRandom());
				c.setRandom();
				String challenge = c.getChallenge();

				// send encrypted random # + challenge with fs public key
				String s = random + "||" + challenge;
				System.out.println("\nCL Random + Challenge -> FS:\n" + s);
				output.writeObject(c.encrypt("RSA/ECB/PKCS1Padding", s, fsPub));
				output.flush();

				// read pseudo-random number from FS
				String clRand = c.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv);
				System.out.println("\nGS Random -> CL:\n" + clRand);

				byte[] ka = c.createChecksum(random + clRand); // SHA256(Ra||Rb)
				byte[] kb = c.createChecksum(clRand + random); // SHA256(Rb||Ra)
				veriK = c.makeAESKeyFromString(kb);
				c.setVeriK(veriK); // set verification key

				// decrypt with private key to get aes key
				c.setAESKey(c.byteToString(ka));
				sharedKey = c.getAESKey();
				System.out.println("\nFS Shared Key: " + sharedKey);
				System.out.println("\nFS Shared Verification Key: " + veriK);

				// send SHA256 checksum of symmetric key for verification
				byte[] checksum = c.createChecksum(s); // create checksum
				System.out.println(s);
				output.writeObject(checksum); // send checksum
				System.out.println("Checksum -> FS:\n" + c.toString(checksum)); // print
				output.flush();

				// send signed checksum
				byte[] signedChecksum = c.signChecksum(checksum);
				output.writeObject(signedChecksum);
				output.flush();

				byte[] Rchallenge = input.readObject().toString().getBytes();
				if (!c.isEqual(challenge.getBytes(), Rchallenge)) {
					System.out.println("Error valiating challenge!");
					System.out.println("Terminating connection!!");
					System.exit(0);
				}
				System.out.println("CHALLENGE VALIDATED: " + c.isEqual(challenge.getBytes(), Rchallenge));
				System.out.println("\n############# CONNETION TO FILESERVER SECURE ############\n");
			}

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (IllegalArgumentException e2) {
			System.err.println("Invalid Port # ?");
			e2.printStackTrace();
		} catch (ClassNotFoundException e3) {
			e3.printStackTrace();
		}

		System.out.println("Connection Status: " + isConnected());
		return isConnected();
	}

	public boolean isConnected() {
		if (sock == null || !sock.isConnected()) {
			return false;
		} else {
			return true;
		}
	}

	public void disconnect() {
		if (isConnected()) {
			try {
				Envelope message = new Envelope("DISCONNECT");
				output.writeObject(message);
				output.flush();
			} catch (Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
