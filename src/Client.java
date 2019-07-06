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

			// literally just for testing so the file server doesn't poop out.
			if (!type.equals("file")) {
				System.out.println("\n\n########### ATTEMPTING TO SECURE CONNECTION ###########");
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
				System.out.println("\n########### CONNECTION IS  SECURE ###########\n\n");

			} else {

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
