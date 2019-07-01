
/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.util.Base64;

// security packages
import java.security.*;
import javax.crypto.spec.*;
import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread {
	private final Socket socket;
	private GroupServer my_gs;

	public GroupThread(Socket _socket, GroupServer _gs) {
		socket = _socket;
		my_gs = _gs;
	}

	public void run() {
		boolean proceed = true;

		try {
			// Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			KeyPair keyPair = genKeyPair(); // generate group thread keypair

			// System.out.println(keyPair.getPublic());
			// System.out.println(keyPair.getPrivate());

			PublicKey clientK = (PublicKey) input.readObject(); // get client key from buffer
			System.out.println("Received client's public key: \n" + clientK);

			if(my_gs.tcList.pubkeys != null){
				// Check to see if ip:pubkey pair exists yet.
				if(my_gs.tcList.pubkeys.containsKey(socket.getInetAddress().toString())){
					// If the ip is there, make sure that the pubkey matches.
					PublicKey storedCliKey = my_gs.tcList.pubkeys.get(socket.getInetAddress().toString());
					if(!storedCliKey.equals(clientK)){
						System.out.println("The stored fingerprint does not match the incoming client key!");
						System.out.println("Terminating connection...");
						socket.close(); // Close the socket
						proceed = false; // End this communication loop
					}
					// The keys match, it's safe to proceed
					else{
						System.out.println("Fingerprint verified!");
					}
				}
				// IP does not yet exist in trusted client list. Add it.
				else{
					System.out.println("This is your first time connecting this client to the group server.");
					System.out.println("Adding client's public key to trusted clients list...");
					my_gs.tcList.addClient(socket.getInetAddress().toString(), clientK);
				}
			}


			Key aesKey = genAESKey(); // generate symmetric AES key
			System.out.println("Generated AES Key:" + Base64.getEncoder().encodeToString(aesKey.getEncoded()));

			System.out.println("\nSending GS public key to client: " + keyPair.getPublic());
			output.writeObject(keyPair.getPublic()); // send GS public key
			byte[] encrypted = encrypt("RSA/ECB/PKCS1Padding", Base64.getEncoder().encodeToString(aesKey.getEncoded()),
					clientK);
			System.out.println("Sending encrypted symmetric key to client:\n" + new String(encrypted));
			output.writeObject(encrypted); // encrypt AES key with client's public then send to client
			System.out.println("Sending signed HMAC to client");
			output.writeObject("HMAC");

			do {
				Envelope message = (Envelope) input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response;

				if (message.getMessage().equals("GET"))// Client wants a token
				{
					String username = (String) message.getObjContents().get(0); // Get the username
					if (username == null) {
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					} else {
						UserToken yourToken = createToken(username); // Create a token

						// Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");
						response.addObject(yourToken);
						output.writeObject(response);
					}
				} else if (message.getMessage().equals("CUSER")) // Client wants to create a user
				{
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								String username = (String) message.getObjContents().get(0); // Extract the username
								UserToken yourToken = (UserToken) message.getObjContents().get(1); // Extract the token

								if (createUser(username, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}

					output.writeObject(response);
				} else if (message.getMessage().equals("DUSER")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								String username = (String) message.getObjContents().get(0); // Extract the username
								UserToken yourToken = (UserToken) message.getObjContents().get(1); // Extract the token

								if (deleteUser(username, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}

					output.writeObject(response);
				} else if (message.getMessage().equals("CGROUP")) // Client wants to create a group
				{
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								String groupName = (String) message.getObjContents().get(0); // Extract the groupname
								UserToken yourToken = (UserToken) message.getObjContents().get(1); // Extract the token

								if (createGroup(groupName, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("DGROUP")) // Client wants to delete a group
				{
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								String groupName = (String) message.getObjContents().get(0); // Extract the groupname
								UserToken yourToken = (UserToken) message.getObjContents().get(1); // Extract the token

								if (deleteGroup(groupName, yourToken)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("LMEMBERS")) // Client wants a list of members in a group
				{
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								String groupName = (String) message.getObjContents().get(0); // Extract the groupname
								UserToken yourToken = (UserToken) message.getObjContents().get(1); // Extract the token

								ArrayList<String> memList = listUsers(groupName, yourToken);
								if (memList == null)
									response = new Envelope("FAIL"); // fail
								else {
									response = new Envelope("OK"); // Success
									response.addObject(memList);
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("AUSERTOGROUP")) // Client wants to add user to a group
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									String userName = (String) message.getObjContents().get(0); // extract the username
									String groupName = (String) message.getObjContents().get(1); // Extract the
																									// groupname
									UserToken yourToken = (UserToken) message.getObjContents().get(2); // Extract the
																										// token
									if (addUserToGroup(userName, groupName, yourToken)) {
										response = new Envelope("OK"); // success
									}
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("RUSERFROMGROUP")) // Client wants to remove user from a group
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									String userName = (String) message.getObjContents().get(0); // extract the username
									String groupName = (String) message.getObjContents().get(1); // Extract the
																									// groupname
									UserToken yourToken = (UserToken) message.getObjContents().get(2); // Extract the
																										// token
									if (deleteUserFromGroup(userName, groupName, yourToken)) {
										response = new Envelope("OK"); // success
									}
								}
							}
						}
					}
					output.writeObject(response);
				}

				else if (message.getMessage().equals("DISCONNECT")) // Client wants to disconnect
				{
					socket.close(); // Close the socket
					proceed = false; // End this communication loop
				} else {
					response = new Envelope("FAIL"); // Server does not understand client request
					output.writeObject(response);
				}
			} while (proceed);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
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

	/*
	 * Method to generate public/private AES symmetric key after client public key
	 * received
	 *
	 * @return key - AES symmetric key
	 */
	private Key genAESKey() {
		Key key = null;
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); // add security provider
			KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
			keyGen.init(128);
			key = keyGen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e2) {
			e2.printStackTrace();
		}
		return key;
	}

	/*
	 * Encryption method
	 *
	 * @return encrypted - encrypted byte value
	 */
	private byte[] encrypt(final String type, final String plaintext, final Key key) {
		byte[] encrypted = null;
		try {
			final Cipher cipher = Cipher.getInstance(type);
			cipher.init(Cipher.ENCRYPT_MODE, key);
			encrypted = cipher.doFinal(plaintext.getBytes());
		} catch (Exception e) {
			System.out.println("The Exception is=" + e);
		}
		return encrypted;
	}

	// Method to create tokens
	private UserToken createToken(String username) {
		// Check that user exists
		if (my_gs.userList.checkUser(username)) {
			// Issue a new token with server's name, user's name, and user's groups
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username));
			return yourToken;
		} else {
			return null;
		}
	}

	// Method to create a user
	private boolean createUser(String username, UserToken yourToken) {
		String requester = yourToken.getSubject();

		// Check if requester exists
		if (my_gs.userList.checkUser(requester)) {
			// Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// requester needs to be an administrator
			if (temp.contains("ADMIN")) {
				// Does user already exist?
				if (my_gs.userList.checkUser(username)) {
					return false; // User already exists
				} else {
					my_gs.userList.addUser(username);
					return true;
				}
			} else {
				return false; // requester not an administrator
			}
		} else {
			return false; // requester does not exist
		}
	}

	// Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken) {
		String requester = yourToken.getSubject();

		// Does requester exist?
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// requester needs to be an administer
			if (temp.contains("ADMIN")) {
				// Does user exist?
				if (my_gs.userList.checkUser(username)) {
					// User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();

					// This will produce a hard copy of the list of groups this user belongs
					for (int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
					}

					// If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

					// Make a hard copy of the user's ownership list
					for (int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}

					// Delete owned groups
					for (int index = 0; index < deleteOwnedGroup.size(); index++) {
						// Use the delete group method. Token must be created for this action
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup));
					}

					// Delete the user from the user list
					my_gs.userList.deleteUser(username);

					return true;
				} else {
					return false; // User does not exist

				}
			} else {
				return false; // requester is not an administer
			}
		} else {
			return false; // requester does not exist
		}
	}

	private boolean createGroup(String groupName, UserToken token) {
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			// no need to check permission because any user can create a group
			// using a set no need to check for dupes, false if contains dupes
			// user who creates group owns group but creator is not added to group by
			// default
			boolean success = my_gs.userList.createGroup(groupName);
			my_gs.userList.addOwnership(requester, groupName);
			return success;
		} else
			return false;
	}

	private boolean deleteGroup(String groupName, UserToken token) {
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			// only the owner(ceator) of group can delete the group
			if (temp.contains(groupName)) {
				// remove group from all users that are a member of the group
				Set<String> allUsers = my_gs.userList.list.keySet();
				for (String user : allUsers) {
					my_gs.userList.removeGroup(user, groupName);
				}
				return my_gs.userList.deleteGroup(groupName);
			} else
				return false;
		} else
			return false;
	}

	private ArrayList<String> listUsers(String groupName, UserToken token) {
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			if (temp.contains(groupName)) {
				return my_gs.userList.getGroupMembers(groupName);
			} else
				return null;
		} else
			return null;
	}

	private boolean addUserToGroup(String user, String groupName, UserToken token) {
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			if (temp.contains(groupName)) {
				my_gs.userList.addGroup(user, groupName);
				return true;
			} else
				return false;
		} else
			return false;
	}

	private boolean deleteUserFromGroup(String user, String groupName, UserToken token) {
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			// check to see if the requestor is the group owner
			if (temp.contains(groupName)) {
				ArrayList<String> userGroups = my_gs.userList.getUserGroups(user);
				// check to see if the user(to be removed) is a member of the group
				if (userGroups.contains(groupName)) {
					my_gs.userList.removeGroup(user, groupName);
					return true;
				} else {
					System.out.println("User groups doesn't contain group.");
					return false;
				}
			} else {
				System.out.println("Requestor doesn't own the group.");
				return false;
			}
		} else {
			System.out.println("Requester doesn't exist.");
			return false;
		}
	}
}
