import java.net.Socket;
import java.net.UnknownHostException;
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

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
	PublicKey groupK;
	public final String clientConfig = "CL";
	Key pub;
	PrivateKey priv;
	Crypto crypto = new Crypto();
	SecretKey sharedKey;
	PublicKey FSpub;

	// Added extra parameter to determine if type is file server or group server.
	// type should be "file" or "group"
	public boolean connect(final String server, final int port, final String type) {

		// fileK will come from file server but doesn't exist yet
		PublicKey fileK = null;

		// Check if socket is in use
		// if (isConnected())
		// disconnect();

		// check if client keys exist
		final String path = "./" + clientConfig + "public.key";
		final String path2 = "./" + clientConfig + "private.key";
		File f = new File(path);
		File f2 = new File(path2);

		// if key files don't exist, create new ones
		if (!f.exists() && !f2.exists()) {
			System.out.println("CL key NOT found!");
			crypto.setSystemKP(clientConfig);
		}

		// now they should exist, set public/private key
		if (f.exists() && f2.exists()) {
			System.out.println("CL keys found!\nSetting public/private key");
			crypto.setPublicKey(clientConfig);
			crypto.setPrivateKey(clientConfig);
			pub = crypto.getPublic();
			priv = crypto.getPrivate();
		}
		// System.out.println(crypto.getPublic());
		System.out.println(crypto.getPublicK());

		// Try to create new socket connection
		try {
			System.out.println("Attempting to connect");
			sock = new Socket(server, port); // create Stream socket then connect to named host @ port #
			System.out.println("Connected to " + server + " on port " + port);

			// If we instantiate input before output, we get into a weird infinite loop
			// situation. :shrug:
			output = new ObjectOutputStream(sock.getOutputStream()); // send output to socket
			input = new ObjectInputStream(sock.getInputStream()); // get input from socket

			// literally just for testing so the file server doesn't poop out.
			if (!type.equals("file")) {
				System.out.println("\n\n########### SECURING GROUP CONNECTION ###########");
				System.out.println("CL public key -> GS\n");
				output.writeObject(crypto.getPublic()); // write public key to channel (encoded)
				output.flush();

				crypto.setClient(input.readObject()); // read client public key (encoded)
				groupK = crypto.getClient();
				System.out.println("Received GS's public key: \n" + crypto.toString(groupK));

				String aesKey = crypto.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(),
						crypto.getPrivate()); // AES
				System.out.println("Received AES key -> " + aesKey);
				crypto.setAESkey(aesKey);
				sharedKey = crypto.getAESKey();

				MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] _checkSum = (byte[]) input.readObject(); // checksum

				System.out.println(
						"Checksum verified -> " + crypto.isEqual(_checkSum, crypto.createChecksum(crypto.getAESKey())));

				// Verify RSA signature
				byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum
				// Signature sig = Signature.getInstance("SHA256withRSA");
				// sig.initVerify(groupK);
				// sig.update(_checkSum);

				System.out.println("Verified Signature -> " + crypto.verifySignature(_checkSum, signedChecksum));
				System.out.println("\n########### CONNECTION TO GROUP SECURE ###########\n\n");

			} else {
				System.out.println("\n\n########### SECURING FILESERVER CONNECTION ###########");

				crypto.setClient(input.readObject()); // read fs public key (encoded)
				FSpub = crypto.getClient();
				System.out.println("Received FS's public key: \n" + crypto.toString(FSpub));

				// if (my_gs.tcList.pubkeys != null) {
				// // Check to see if ip:pubkey pair exists yet.
				// if (my_gs.tcList.pubkeys.containsKey(socket.getInetAddress().toString())) {
				// // If the ip is there, make sure that the pubkey matches.
				// PublicKey storedCliKey =
				// my_gs.tcList.pubkeys.get(socket.getInetAddress().toString());
				// if (!storedCliKey.equals(clientK)) {
				// System.out.println("The stored fingerprint does not match the incoming client
				// key!");
				// System.out.println("Terminating connection...");
				// socket.close(); // Close the socket
				// proceed = false; // End this communication loop
				// }
				// // The keys match, it's safe to proceed
				// else {
				// System.out.println("Fingerprint verified!");
				// }
				// }
				// // IP does not yet exist in trusted client list. Add it.
				// else {
				// System.out.println("This is your first time connecting this client to the
				// group server.");
				// System.out.println("Adding client's public key to trusted clients list...");
				// my_gs.tcList.addClient(socket.getInetAddress().toString(), clientK);
				// }
				// }

				// send client's public key to client
				output.writeObject(crypto.getPublic());
				System.out.println("\nClient public key -> FS: " + crypto.toString(crypto.getPublic()));

				// send symmetric key AND CHALLENGE encrypted with fs's public key with padding
				crypto.setAESkey(); // create AES key
				String challenge = crypto.getChallenge();
				System.out.println(challenge);

				SecretKey _aesKey = crypto.getAESKey();
				output.writeObject(crypto.encrypt("RSA/ECB/PKCS1Padding", crypto.toString(_aesKey) + challenge, FSpub));
				System.out.println("\nAES key -> Client: " + crypto.toString(_aesKey));

				// send SHA256 checksum of symmetric key for verification
				// MessageDigest digest = MessageDigest.getInstance("SHA-256");
				byte[] checksum = crypto.createChecksum(_aesKey);
				output.writeObject(crypto.createChecksum(_aesKey)); // send checksum
				System.out.println("Checksum -> Client: " + crypto.toString(checksum));

				System.out.println("\n########### CONNECTION TO FILESERVER SECURE ###########\n\n");
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
		} catch (NoSuchAlgorithmException e4) {
			e4.printStackTrace();
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
			} catch (Exception e) {
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}
	}
}
