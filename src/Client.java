import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.lang.Byte;

// security packages
import java.security.*;
import javax.crypto.spec.*;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Client {

	/*
	 * protected keyword is like private but subclasses have access Socket and
	 * input/output streams
	 */
	protected Socket sock;
	protected ObjectOutputStream output;
	protected ObjectInputStream input;

	public boolean connect(final String server, final int port) {

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

			System.out.println("Generating Client RSA keypair");
			KeyPair keyPair = genKeyPair();
			System.out.println(keyPair.getPublic());
			System.out.println(keyPair.getPrivate());

			System.out.println("Writing public key to Group Server\n");
			output.writeObject(keyPair.getPublic()); // write public key to channel

			try {
				PublicKey clientK = (PublicKey) input.readObject(); // get gs key from buffer
				System.out.println("Group server public key received:\n" + clientK);
				String aesKey = decrypt("RSA", (byte[]) input.readObject(), keyPair.getPrivate());
				System.out.println("Encrypted AES key Received:\n" + aesKey); // need serializable?
				String hello = (String) input.readObject();
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
			}

		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (IllegalArgumentException e2) {
			System.err.println("Invalid Port # ?");
			e2.printStackTrace();
		}
		return isConnected();
	}

	private String decrypt(final String type, final byte[] encrypted, final Key key) {
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
