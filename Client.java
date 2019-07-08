import java.net.Socket;
import java.net.UnknownHostException;
import java.io.*;
import java.util.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;
import javax.crypto.Mac;

public abstract class Client {

	/*
	 * protected keyword is like private but subclasses have access Socket and
	 * input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	//String keyFile = "ClientKeyPair.bin";
	String tfsFile = "TrustedFServer.bin";
	TrustedFServer tfsList;
	ObjectInputStream tfsStream;

	// crypto stuff

	protected Crypto c;
	PublicKey pub; // clien'ts publickey
	PrivateKey priv; // client's private key
	SecretKey sharedKey; // symmetric AES key
	PublicKey fsPub; // fileserver public key

	// accessible in FileClient thread
	static PublicKey groupK;
	static byte[] fsMac;
	// KeyPair keyPair;
	// ObjectInputStream keyPairStream;

	public boolean connect(final String server, final int port, final String type, final String clientNum) {
		fsMac = null;

		String clientConfig = "CL" + clientNum;

		// set client key file paths
		final String path = "./" + clientConfig + "public.key";
		final String path2 = "./" + clientConfig + "private.key";
		File f = new File(path);
		File f2 = new File(path2);
		c = new Crypto();

		// if key files don't exist, create new ones
		if (!f.exists() && !f2.exists()) {
			System.out.println("CL key NOT found!");
			c.setSystemKP(clientConfig);
		}

		// now they should exist, set public/private key
		if (f.exists() && f2.exists()) {
			System.out.println("CL keys found!\nSetting public/private key");
			c.setPublicKey(clientConfig);
			c.setPrivateKey(clientConfig);
			pub = c.getPublic();
			priv = c.getPrivate();
		}
		System.out.println(c.RSAtoString(pub)); // print out public key base64

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
		System.out.println("###########################################");

		// Try to create new socket connection
		try {
			sock = new Socket(server, port); // create Stream socket then connect to named host @ port #
			System.out.println("\nConnected to " + server + " on port " + port);
			output = new ObjectOutputStream(sock.getOutputStream()); // send output to socket
			input = new ObjectInputStream(sock.getInputStream()); // get input from socket

			// Group Server connection
			if (!type.equals("file")) {
				System.out.println("\n\n########### ATTEMPT TO SECURE GS CONNECTION ###########");
				System.out.println("CL public key -> GS\n");
				output.writeObject(pub); // write public key to channel (not encoded)
				output.flush();

				// get gs publickey
				c.setSysK(input.readObject()); // read gs public key (encoded)
				groupK = c.getSysK();
				System.out.println("Received GS's public key: \n" + c.RSAtoString(groupK));

				// decrypt with private key to get aes key
				String aesKey = c.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv); // AES
				c.setAESKey(aesKey);
				sharedKey = c.getAESKey();
				System.out.println("Received AES key -> " + c.toString(sharedKey));

				// verify checksum
				byte[] _checkSum = (byte[]) input.readObject(); // read checksum
				System.out.println("Checksum:\n" + c.toString(_checkSum)); // print
				System.out.println("Checksum verified -> " + c.isEqual(_checkSum, c.createChecksum(aesKey)));

				// verify signature
				byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum
				System.out.println("Signed Checksum: " + c.toString(signedChecksum));
				System.out.println("############## CONNECTION TO GS SECURE ##############\n");

			} else {
				System.out.println("Received GS's public key: \n" + c.RSAtoString(groupK));
				System.out.println("\n\n########### ATTEMPT TO SECURE FS CONNECTION ###########");

				c.setSysK(input.readObject()); // read fs public key not encoded
				fsPub = c.getSysK(); // set FS pub key
				System.out.println("Received FS's public key: \n" + c.RSAtoString(fsPub));

				// send client's public key to client
				output.writeObject(pub);
				output.flush();
				System.out.println("\nClient public key -> FS:\n" + c.RSAtoString(pub));

				if(tfsList == null){
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
							}
							else{
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
						System.out.println("Adding server's public key to trusted file server list...");
						tfsList.addServer(sock.getInetAddress().toString(), fsPub);
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

				// generate aes key + challenge
				c.genAESKey(); // create AES key
				sharedKey = c.getAESKey();
				String challenge = c.getChallenge();
				System.out.println("\nAES key: " + c.toString(sharedKey));
				System.out.println("Challenge: " + challenge);

				// send encrypted aeskey + challenge with fs public key
				String s = c.toString(sharedKey) + challenge;
				output.writeObject(c.encrypt("RSA/ECB/PKCS1Padding", s, fsPub));
				output.flush();

				// send SHA256 checksum of symmetric key for verification
				byte[] checksum = c.createChecksum(s); // create checksum w aes
														// key
				output.writeObject(checksum); // send checksum
				System.out.println("Checksum -> FS:\n" + c.toString(checksum)); // print
				output.flush();

				// send signed checksum
				byte[] signedChecksum = c.signChecksum(checksum);
				output.writeObject(signedChecksum);
				System.out.println("Signed Checksum -> Client:\n" + c.toString(signedChecksum));
				output.flush();

				System.out.println("CHALLENGE VALIDATED: "
						+ c.isEqual(challenge.getBytes(), input.readObject().toString().getBytes()));
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