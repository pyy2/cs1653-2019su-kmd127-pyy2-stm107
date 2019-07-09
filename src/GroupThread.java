
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
import javax.crypto.*;
import javax.crypto.Mac;
import java.security.Signature;

import javax.crypto.spec.*;
import java.security.Key;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupThread extends Thread {
	private final Socket socket;
	protected GroupServer my_gs;
	PublicKey pub; // group public key
	PrivateKey priv; // group's private key
	SecretKey _aesKey; // AES symmetric key
	PublicKey clientK; // client's public key
	Crypto gc;
	Scanner in = new Scanner(System.in);

	public GroupThread(Socket _socket, GroupServer _gs) {
		socket = _socket;
		my_gs = _gs;
		gc = new Crypto();
		pub = null;
		priv = null;
		_aesKey = null;
		clientK = null;
	}

	public void run() {
		boolean proceed = true;

		try {
			// Announces connection and opens object streams
			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			// set gs key file paths
			final String path = "./GSpublic.key";
			final String path2 = "./GSprivate.key";
			File f = new File(path);
			File f2 = new File(path2);

			// if key files don't exist, something went wrong on initialization, ABORT
			if (!f.exists() && !f2.exists()) {
				System.out.println("FATAL ERROR: GS key NOT found!\nSystem Exiting");
				System.exit(1);
			} else if ((pub == null) && (priv == null)) {
				System.out.println("Setting GS public/private keys");
				gc.setPublicKey("GS");
				gc.setPrivateKey("GS");
				pub = gc.getPublic();
				priv = gc.getPrivate();
			} else {
				System.out.println("GS Keys already set!");
			}

			System.out.println("\n########### ATTEMPT TO SECURE CL CONNECTION ###########");
			gc.setSysK(input.readObject()); // read client public key (not encoded)
			clientK = gc.getSysK();
			System.out.println("Received client's public key: \n" + gc.RSAtoString(clientK));

			if (my_gs.tcList.pubkeys != null) {
				// Check to see if ip:pubkey pair exists yet.
				if (my_gs.tcList.pubkeys.containsKey(socket.getInetAddress().toString())) {
					// If the ip is there, make sure that the pubkey matches.
					// System.out.println("This is the contents of the trusted client file: ");
					// System.out.println(my_gs.tcList.pubkeys);
					// System.out.println("\n\n\n");
					List<PublicKey> storedCliKeys = my_gs.tcList.pubkeys.get(socket.getInetAddress().toString());
					if (!storedCliKeys.contains(clientK)) {
						// prompt group client to see if they want to add ip:pubkey pair
						// modified to let multiple clients connect if gs allows the connection
						// or else it blocks because the keypairs generated for each client is different
						Scanner in = new Scanner(System.in);
						System.out.println("Warning: stored fingerprint do not match the incoming client key!");
						System.out.println("Continue letting client connect? (y/n)");
						if (in.next().charAt(0) == 'y') {
							System.out.println("Adding client's public key to trusted clients list...");
							my_gs.tcList.addClient(socket.getInetAddress().toString(), clientK);
							// System.out.println("This is the contents of the trusted client file AFTER
							// ADDING: ");
							// System.out.println(my_gs.tcList.pubkeys);
							// System.out.println("\n\n\n");
						} else {
							System.out.println("Terminating connection...");
							socket.close(); // Close the socket
							proceed = false; // End this communication loop
						}
					}
					// The keys match, it's safe to proceed
					else {
						System.out.println("Client Fingerprint verified!");
					}
				}
				// IP does not yet exist in trusted client list. Add it.
				else {
					System.out.println("This is your first time connecting this client to the group server.");
					System.out.println("Adding client's public key to trusted clients list...");
					my_gs.tcList.addClient(socket.getInetAddress().toString(), clientK);
				}
			}

			// send group server public key to client
			output.writeObject(pub);
			// System.out.println("\nGS public key -> client:\n" + gc.RSAtoString(pub));

			// send symmetric key encrypted with client's public key with padding
			gc.genAESKey(); // create AES key
			_aesKey = gc.getAESKey();
			output.writeObject(gc.encrypt("RSA/ECB/PKCS1Padding", gc.toString(_aesKey), clientK));
			// System.out.println("\nAES key -> Client:\n" + gc.toString(_aesKey));

			// send SHA256 checksum of symmetric key for verification
			byte[] checksum = gc.createChecksum(gc.toString(_aesKey)); // create checksum w aes key
			output.writeObject(checksum); // send checksum
			// System.out.println("Checksum -> Client:\n" + gc.toString(checksum)); // print

			// send signed checksum
			byte[] signedChecksum = gc.signChecksum(checksum);
			output.writeObject(signedChecksum);
			output.flush();
			// System.out.println("Signed Checksum -> Client:\n" +
			// gc.toString(signedChecksum));
			System.out.println("\n########### GS CONNECTION W CLIENT SECURE ###########\n");

			do {
				Envelope message = (Envelope) input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response = null;
				clientK = gc.getSysK();

				if (message.getMessage().equals("GET"))// Client wants a token
				{
					byte[] uname = (byte[]) message.getObjContents().get(0);
					String username = gc.decrypt("AES", uname, _aesKey);
					if (username == null) {
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					} else {
						UserToken yourToken = createToken(username); // Create a token

						// Respond to the client. On error, the client will receive a null token
						response = new Envelope("OK");

						// First, stringify everything
						String pubKey = gc.toString(gc.getPublic());
						// System.out.println("OUTPUT" + pubKey);
						String token = null;
						if (yourToken != null) {
							token = yourToken.toString();
						}

						// Concat token with pubkey and encrypt with shared key.
						String concatted = pubKey + "||" + token;
						byte[] bconcatted = concatted.getBytes();

						// Encrypt with shared key
						byte[] encryptedToken = gc.encrypt("AES", concatted, _aesKey);

						// System.out.println(concatted);
						// Then HMAC(pubkey || token, ClientKey) and sign
						Mac mac = Mac.getInstance("HmacSHA256", "BC");
						mac.init(clientK);
						mac.update(bconcatted);
						byte[] out = mac.doFinal();
						byte[] signed_data = gc.signChecksum(out);

						response.addObject(encryptedToken);
						response.addObject(out);
						response.addObject(signed_data);
						output.writeObject(response);
					}
				} else if (message.getMessage().equals("CUSER")) // Client wants to create a user
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String username = p_arr[0];
									String password = p_arr[1];
									UserToken yourToken = makeTokenFromString(p_arr[2]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (createUser(username, password, yourToken)) {
										// we're just sending back "OK", so we probably don't need to worry about
										// encrypting.
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("CPWD")) // Client wants to for password match
				{
					if (message.getObjContents().size() < 1) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							byte[] uname = (byte[]) message.getObjContents().get(0);
							String[] upwd = gc.decrypt("AES", uname, _aesKey).split(";");
							String username = upwd[0];
							String password = upwd[1];
							System.out.println("This is the username: "+ username);
							System.out.println("This is the password: " + password);
							if (checkPassword(username, password)) {
								response = new Envelope("OK"); // Success
							}
						}
					}
					// Doesn't really need to be encrypted since it's just sending "ok" of "fail"
					output.writeObject(response);
				} else if (message.getMessage().equals("FLOGIN")) {
					if (message.getObjContents().size() < 1) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							byte[] uname = (byte[]) message.getObjContents().get(0);
							String username = gc.decrypt("AES", uname, _aesKey);

							if (firstLogin(username)) {
								response = new Envelope("OK"); // Success
							}
						}
					}
					// Doesn't really need to be encrypted since it's just sending "ok" of "fail"
					output.writeObject(response);
				} else if (message.getMessage().equals("RPASS")) // Client wants to reset password
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] uname = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String[] upwd = gc.decrypt("AES", uname, _aesKey).split(";");
									String username = upwd[0];
									String password = upwd[1];

									if (!gc.verifyHmac((username + password).getBytes(), hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (resetPassword(username, password)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					// Doesn't really need to be encrypted since it's just sending "ok" of "fail"
					output.writeObject(response);
				} else if (message.getMessage().equals("UNLOCK")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String username = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (unlockUser(username)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}

					output.writeObject(response);
				} else if (message.getMessage().equals("LOCK")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String username = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (lockUser(username)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}

					output.writeObject(response);
				} else if (message.getMessage().equals("DUSER")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String username = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (deleteUser(username, yourToken)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}

					output.writeObject(response);
				} else if (message.getMessage().equals("CGROUP")) // Client wants to create a group
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String groupName = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (createGroup(groupName, yourToken)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("DGROUP")) // Client wants to delete a group
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String groupName = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									if (deleteGroup(groupName, yourToken)) {
										response = new Envelope("OK"); // Success
									}
								}
							}
						}
					}
					output.writeObject(response);
				} else if (message.getMessage().equals("LMEMBERS")) // Client wants a list of members in a group
				{
					if (message.getObjContents().size() < 3) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String groupName = p_arr[0];
									UserToken yourToken = makeTokenFromString(p_arr[1]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
									ArrayList<String> memList = listUsers(groupName, yourToken);
									if (memList == null)
										response = new Envelope("FAIL"); // fail
									else {
										response = new Envelope("OK"); // Success
										// probably ok to just encrypt with shared key
										byte[] enc_memList = gc.createEncryptedString(memList);
										response.addObject(enc_memList);
									}
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
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String userName = p_arr[0];
									String groupName = p_arr[1];
									UserToken yourToken = makeTokenFromString(p_arr[2]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
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
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									String[] p_arr = params.split("-");

									String userName = p_arr[0];
									String groupName = p_arr[1];
									UserToken yourToken = makeTokenFromString(p_arr[2]);

									if (!gc.verifyHmac(enc_params, hmac)) {
										output.writeObject(response);
										return;
									}
									if (!gc.verifySignature(hmac, signed_data)) {
										output.writeObject(response);
										return;
									}
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

	// Method to verify password match.
	private boolean checkPassword(String username, String pwd) {
		if (my_gs.userList.checkUser(username)) {
			if (my_gs.userList.checkPassword(username, pwd)) {
				return true;
			}
			return false;
		} else {
			return false;
		}
	}

	// Method to check if password needs reset
	private boolean firstLogin(String username) {
		if (my_gs.userList.checkUser(username)) {
			if (my_gs.userList.firstLogin(username)) {
				return true;
			}
			return false;
		} else {
			return false;
		}
	}

	// Method to reset password.
	private boolean resetPassword(String username, String pwd) {
		if (my_gs.userList.checkUser(username)) {
			if (my_gs.userList.resetPassword(username, pwd)) {
				return true;
			}
			return false;
		} else {
			return false;
		}
	}

	// Method to create a user
	private boolean createUser(String username, String password, UserToken yourToken) {
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
					my_gs.userList.addUser(username, password);
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

	private boolean unlockUser(String username) {
		return my_gs.userList.list.get(username).unlockUser();
	}

	private boolean lockUser(String username) {
		return my_gs.userList.list.get(username).lockUser();
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
				my_gs.userList.removeOwnership(requester, groupName);
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
		if (my_gs.userList.checkUser(requester) && my_gs.userList.checkUser(user)) {
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
			if (temp.contains(groupName) && my_gs.userList.checkUser(user)) {
				ArrayList<String> userGroups = my_gs.userList.getUserGroups(user);
				// check to see if the user(to be removed) is a member of the group
				if (userGroups != null && userGroups.contains(groupName)) {
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

	private UserToken makeTokenFromString(String tokenString) {
		String[] tokenComps = tokenString.split(";");
		String issuer = tokenComps[0];
		String subject = tokenComps[1];
		List<String> groups = new ArrayList<>();
		for (int i = 2; i < tokenComps.length; i++) {
			groups.add(tokenComps[i]);
		}
		return new Token(issuer, subject, groups);
	}
}
