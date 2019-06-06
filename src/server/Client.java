import java.net.Socket;
import java.net.UnknownHostException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

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
			this.sock = new Socket(server, port); // create Stream socket then connect to named host @ port #
			System.out.println("Connected to " + server + " on port " + port);

			this.input = new ObjectInputStream(sock.getInputStream()); // get input from socket
			this.output = new ObjectOutputStream(sock.getOutputStream()); // send output to socket
		} catch (UnknownHostException e) {
			System.err.println(e);
			e.printStackTrace();
		} catch (IOException e1) {
			System.err.println(e1);
			e1.printStackTrace();
		} catch (IllegalArgumentException e2) {
			System.out.println("Invalid Port #");
			System.err.println(e2);
			e2.printStackTrace();
		}

		// Return connection status
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
