import java.net.Socket;
import java.net.UnknownHostException;
import java.io.*;

import java.util.*;

// security packages
import java.security.*;
import javax.crypto.spec.*;
import javax.crypto.Cipher;
import java.security.Signature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Client {

	/*
	 * protected keyword is like private but subclasses have access Socket and
	 * input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;
	String keyFile = "ClientKeyPair.bin";
	String tfsFile = "TrustedFServer.bin";
	TrustedFServer tfsList;
	ObjectInputStream tfsStream;
	ObjectInputStream keyPairStream;
	KeyPair keyPair;
	String aesKey;
	Key sharedAES;


	// Added extra parameter to determine if type is file server or group server.
	// type should be "file" or "group"
	public boolean connect(final String server, final int port, final String type) {

		// fileK will come from file server but doesn't exist yet
		PublicKey fileK = null;

		// Check if socket is in use
		if (isConnected())
			disconnect();

		// Try to create new socket connection
		try {
			System.out.println("Attempting to connect");
			sock = new Socket(server, port); // create Stream socket then connect to named host @ port #
			System.out.println("Connected to " + server + " on port " + port);

			// If we instantiate input before output, we get into a weird infinite loop
			// situation. :shrug:
			output = new ObjectOutputStream(sock.getOutputStream()); // send output to socket
			input = new ObjectInputStream(sock.getInputStream()); // get input from socket
			ObjectOutputStream outStream;

			// Only generate a new keypair if there isn't one for this client already.
			// That way, fingerprinting on the group server can occur and the GS can verify
			// on subsequent connections.
			try {
				// Try to read teh keypair from a file.
				FileInputStream fis_keys = new FileInputStream(keyFile);
				keyPairStream = new ObjectInputStream(fis_keys);
				keyPair = (KeyPair) keyPairStream.readObject();
			} catch (FileNotFoundException e) {
				// The file doesn't exist, then there's no RSA keys for this client.
				System.out.println("Generating Client RSA keypair");
				keyPair = genKeyPair();
				System.out.println(keyPair.getPublic());
				System.out.println(keyPair.getPrivate());
				// save the key pair for future use.
				outStream = new ObjectOutputStream(new FileOutputStream(keyFile));
				outStream.writeObject(keyPair);
			} catch (Exception e) {
				System.out.println("Unable to load key pair for this client.");
				System.out.println("Exception: " + e);
			}

			System.out.println("Writing public key to Server\n");

			// literally just for testing so the file server doesn't poop out.
			if(!type.equals("file")){
				output.writeObject(keyPair.getPublic()); // write public key to channel

				try {
					PublicKey groupK = (PublicKey) input.readObject(); // group public key
					aesKey = decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), keyPair.getPrivate()); // AES
					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					byte[] _checkSum = (byte[]) input.readObject(); // checksum
					byte[] checkSum = digest.digest(Base64.getDecoder().decode(aesKey));
					byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum

					// Verify RSA signature
					Signature sig = Signature.getInstance("SHA256withRSA");
					sig.initVerify(groupK);
					sig.update(_checkSum);

					System.out.println("Group server public key -> " + groupK);
					System.out.println("Received AES key ->" + aesKey);
					System.out.println("Checksum -> " + Base64.getEncoder().encodeToString(_checkSum));
					System.out.println("Computed Checksum -> " + Base64.getEncoder().encodeToString(checkSum));
					System.out.println("Verified Signature -> " + sig.verify(signedChecksum));

					// regenerate an AES key object from the AES string
					byte[] decodedKey = Base64.getDecoder().decode(aesKey);
					sharedAES = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

					if (isEqual(_checkSum, checkSum)) {
						System.out.println("====Checksum verified====\n\n");
					} else {
						System.out.println("INVALID CHECKSUM");
						return false;
					}

				} catch (ClassNotFoundException e) {
					e.printStackTrace();
				} catch (NoSuchAlgorithmException e2) {
					e2.printStackTrace();
				} catch (InvalidKeyException e3) {
					e3.printStackTrace();
				} catch (SignatureException e4) {
					e4.printStackTrace();
				}
			}
			// only read in trusted file servers file if this is a file server connection.
			if(type.equals("file")){
				// Get the file server pub key and make sure the fingerprint match.
				// This shouldn't really run right now, since the file server doesn't yet produce keys.
				// Open the trusted file server list
				// try {
				// 	FileInputStream fis_tfs = new FileInputStream(tfsFile);
				// 	tfsStream = new ObjectInputStream(fis_tfs);
				// 	tfsList = (TrustedFServer) tfsStream.readObject();
				// } catch (FileNotFoundException e) {
				// 	System.out.println("No Trusted file servers found!");
				// 	System.out.println("Instantiating Trusted File Server list...");
				// 	tfsList = new TrustedFServer();
				// } catch (Exception e) {
				// 	System.out.println("Unable to load list of trusted file servers.");
				// 	System.out.println("Exception: " + e);
				// }
				// if (tfsList.pubkeys != null) {
				// 	// Check to see if ip:pubkey pair exists yet.
				// 	if (tfsList.pubkeys.containsKey(sock.getInetAddress().toString())) {
				// 		// If the ip is there, make sure that the pubkey matches.
				// 		PublicKey storedFSKey = tfsList.pubkeys.get(sock.getInetAddress().toString());
				// 		if (!storedFSKey.equals(fileK)) {
				// 			System.out.println("The stored fingerprint does not match the incoming file server key!");
				// 			System.out.println("Terminating connection...");
				// 			sock.close(); // Close the socket
				// 		}
				// 		// The keys match, it's safe to proceed
				// 		else {
				// 			System.out.println("Fingerprint verified!");
				// 		}
				// 	}
				// 	// IP does not yet exist in trusted client list. Add it.
				// 	else {
				// 		System.out.println("This is your first time connecting this client to this file server.");
				// 		System.out.println("Adding file server's public key to trusted file servers list...");
				// 		//tfsList.addServer(sock.getInetAddress().toString(), fileK);
				// 		outStream = new ObjectOutputStream(new FileOutputStream(tfsFile));
				// 		outStream.writeObject(tfsList);
				//	}
				//}
			}
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (IllegalArgumentException e2) {
			System.err.println("Invalid Port # ?");
			e2.printStackTrace();
		}

		System.out.println("Connection Status: " + isConnected());
		return isConnected();
	}

	private boolean isEqual(byte[] a, byte[] b) {
		if (a.length != b.length) {
			return false;
		}
		int result = 0;
		for (int i = 0; i < a.length; i++) {
			result |= a[i] ^ b[i];
		}
		return result == 0;
	}

	protected String decrypt(final String type, final byte[] encrypted, final Key key) {
		String decryptedValue = null;
		try {
			final Cipher cipher = Cipher.getInstance(type);
			cipher.init(Cipher.DECRYPT_MODE, key);
			decryptedValue = new String(cipher.doFinal(encrypted));
		} catch (Exception e) {
			System.out.println("The Exception is=" + e);
			e.printStackTrace(System.err);
		}
		return decryptedValue;
	}

	/*
	 * Encryption method
	 *
	 * @return encrypted - encrypted byte value
	 */
	protected byte[] encrypt(final String type, final String plaintext, final Key key) {
		byte[] encrypted = null;
		try {
			final Cipher cipher = Cipher.getInstance(type);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = cipher.doFinal(plaintext.getBytes());
		} catch (Exception e) {
			System.out.println("The Encryption Exception is=" + e);
		}
		return encrypted;
	}

	/*
	 * Method to generate public/private RSA keypair when client attempts to connect
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
			} catch (Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
