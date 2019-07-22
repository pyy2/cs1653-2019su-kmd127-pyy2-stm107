
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
	private static Scanner in;
	String response;

	// local sequence # tracker
	int expseq = 1;

	public GroupThread(Socket _socket, GroupServer _gs) {
		socket = _socket;
		my_gs = _gs;
		gc = new Crypto();
		pub = null;
		priv = null;
		_aesKey = null;
		clientK = null;
		in = new Scanner(System.in);
		response = "";
	}

	public void run() {
		boolean proceed = true;

		try {

			// ####################### HAND SHAKE PROTOCOL #######################//

			// Announces connection and opens object streams
			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");

			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

			// set gs key file paths
			final String path = "./keys/GSpublic.key";
			final String path2 = "./keys/GSprivate.key";
			File f = new File(path);
			File f2 = new File(path2);

			// if key files don't exist, something went wrong on initialization, ABORT
			if (!f.exists() && !f2.exists()) {
				System.out.println("FATAL ERROR: GS key NOT found!\nSystem Exiting");
				System.exit(1);
			}

			if ((pub == null) && (priv == null)) {
				System.out.println("Setting GS public/private keys");
				gc.setPublicKey("GS");
				gc.setPrivateKey("GS");
				pub = gc.getPublic();
				priv = gc.getPrivate();
			} else {
				System.out.println("GS Keys already set!");
			}

			System.out.println("\n\n########### ATTEMPT TO SECURE CL CONNECTION ###########\n");

			// get client's public key
			gc.setSysK(input.readObject()); // read client public key (not encoded)
			clientK = gc.getSysK(); // set client's public key
			System.out.println("CL Public Key -> GS: \n" + gc.RSAtoString(clientK));

			if (my_gs.tcList.pubkeys != null) {
				// Check to see if ip:pubkey pair exists yet.
				if (my_gs.tcList.pubkeys.containsKey(socket.getInetAddress().toString())) {
					// If the ip is there, make sure that the pubkey matches.
					List<PublicKey> storedCliKeys = my_gs.tcList.pubkeys.get(socket.getInetAddress().toString());
					if (!storedCliKeys.contains(clientK)) {
						// prompt group client to see if they want to add ip:pubkey pair
						// modified to let multiple clients connect if gs allows the connection
						// or else it blocks because the keypairs generated for each client is different
						System.out.println("Warning: stored fingerprint do not match the incoming client key!");
						System.out.println("Continue letting client connect? (y/n)");
						if (in.next().charAt(0) == 'y') {
							System.out.println("Adding client's public key to trusted clients list...");
							my_gs.tcList.addClient(socket.getInetAddress().toString(), clientK);
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

			// read pseudo-random number from client
			String clRand = gc.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv);
			gc.setSysRandom(clRand);
			System.out.println("\nCL Random -> GS:\n" + clRand);

			// generate new pseudo-random number and send to CL
			gc.setRandom(); // generate new secure random (32 byte)
			String random = gc.byteToString(gc.getRandom());
			System.out.println("\nGS Random -> CL:\n" + random);
			output.writeObject(gc.encrypt("RSA/ECB/PKCS1Padding", random, clientK)); // encrypt w gs private key
			output.flush();

			byte[] ka = gc.createChecksum(clRand + random); // SHA256(Ra||Rb)
			byte[] kb = gc.createChecksum(random + clRand); // SHA256(Rb||Ra)

			// send symmetric key encrypted with client's public key with padding
			gc.setAESKey(gc.byteToString(ka));
			_aesKey = gc.getAESKey();
			System.out.println("\nShared Key Set: " + _aesKey);

			System.out.println("\n########### GS CONNECTION W CLIENT SECURE ###########\n");

			do {
				Envelope message = (Envelope) input.readObject();
				System.out.println("Request received: " + message.getMessage());
				Envelope response = null;
				clientK = gc.getSysK();

				// ####################### GET TOKEN #######################//

				if (message.getMessage().equals("GET"))// Client wants a token
				{
					byte[] enc_params = (byte[]) message.getObjContents().get(0);

					int seq = (Integer) message.getObjContents().get(1);
					gc.checkSequence(seq, expseq);

					String params = gc.decrypt("AES", enc_params, _aesKey);
					String[] split_params = params.split("-");
					String username = split_params[0];
					String fip = split_params[1];
					int fport = Integer.parseInt(split_params[2]);

					if (username == null) {
						response = new Envelope("FAIL");
						response.addObject(null);
						output.writeObject(response);
					} else {
						if (my_gs.userList.list.get(username).getLockStatus()) {
							System.out.println("This is user is locked!");
							response = new Envelope("LOCKED");
						} else {
							UserToken yourToken = createToken(username, fip, fport); // Create a token

							// Respond to the client. On error, the client will receive a null token
							response = new Envelope("OK");

							// First, stringify everything
							String pubKey = gc.toString(gc.getPublic());
							// System.out.println("OUTPUT" + pubKey);
							String token = null;
							if (yourToken != null) {
								token = yourToken.toString();
							}

							// TODO: Don't send group public key.
							// Concat token with pubkey and encrypt with shared key.
							String concatted = pubKey + "||" + token;
							byte[] bconcatted = concatted.getBytes();

							// Encrypt with shared key
							byte[] encryptedToken = gc.encrypt("AES", concatted, _aesKey);

							// TODO: Don't send public key
							// Then HMAC(pubkey || token, ClientKey) and sign
							Mac mac = Mac.getInstance("HmacSHA256", "BC");
							mac.init(clientK);
							mac.update(bconcatted);
							byte[] out = mac.doFinal();
							byte[] signed_data = gc.signChecksum(out);

							response.addObject(encryptedToken);
							response.addObject(out);
							response.addObject(signed_data);
						}

						response.addObject(++expseq);
						++expseq;
						output.writeObject(response);

					}

					// ####################### CREATE USER #######################//

				} else if (message.getMessage().equals("CUSER")) // Client wants to create a user
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### CHECK PASSWORD #######################//

				} else if (message.getMessage().equals("CPWD")) // Client wants to for password match
				{
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(1);
						gc.checkSequence(seq, expseq);

						if (message.getObjContents().get(0) != null) {
							byte[] uname = (byte[]) message.getObjContents().get(0);
							String[] upwd = gc.decrypt("AES", uname, _aesKey).split(";");
							String username = upwd[0];
							String password = upwd[1];
							if (checkPassword(username, password)) {
								// System.out.println("Do we get here...");
								response = new Envelope("OK"); // Success
							}
						}
					}
					response.addObject(++expseq);
					++expseq;
					// Doesn't really need to be encrypted since it's just sending "ok" of "fail"
					output.writeObject(response);

					// ####################### CHECK IF FIRST LOGIN #######################//

				} else if (message.getMessage().equals("FLOGIN")) {
					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(1);
						gc.checkSequence(seq, expseq);
						if (message.getObjContents().get(0) != null) {
							byte[] uname = (byte[]) message.getObjContents().get(0);
							String username = gc.decrypt("AES", uname, _aesKey);

							if (firstLogin(username)) {
								response = new Envelope("OK"); // Success
							}
						}
					}
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### RESET PASSWORD #######################//

				} else if (message.getMessage().equals("RPASS")) // Client wants to reset password
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] uname = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String temp = gc.decrypt("AES", uname, _aesKey);
									String[] upwd = temp.split(";");
									String username = upwd[0];
									String password = upwd[1];

									if (!gc.verifyHmac(uname, hmac)) {
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### UNLOCK #######################//

				} else if (message.getMessage().equals("UNLOCK")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								int seq = (Integer) message.getObjContents().get(1);
								gc.checkSequence(seq, expseq);

								String uname = gc.decrypt("AES", (byte[]) message.getObjContents().get(0), _aesKey);

								if (unlockUser(uname)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}
					output.writeObject(response);

					// ####################### LOCK (WIP) #######################//

				} else if (message.getMessage().equals("LOCK")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 2) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								int seq = (Integer) message.getObjContents().get(1);
								gc.checkSequence(seq, expseq);
								String uname = gc.decrypt("AES", (byte[]) message.getObjContents().get(0), _aesKey);

								if (lockUser(uname)) {
									response = new Envelope("OK"); // Success
								}
							}
						}
					}
					// response.addObject(++expseq);
					// ++expseq;
					output.writeObject(response);

					// ####################### DELETE USER #######################//

				} else if (message.getMessage().equals("DUSER")) // Client wants to delete a user
				{

					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");

						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								int seq = (Integer) message.getObjContents().get(3);
								gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### CREATE GROUP #######################//

				} else if (message.getMessage().equals("CGROUP")) // Client wants to create a group
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### DELETE GROUP #######################//

				} else if (message.getMessage().equals("DGROUP")) // Client wants to delete a group
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
						if (message.getObjContents().get(0) != null) {
							if (message.getObjContents().get(1) != null) {
								if (message.getObjContents().get(2) != null) {
									byte[] enc_params = (byte[]) message.getObjContents().get(0);
									byte[] hmac = (byte[]) message.getObjContents().get(1);
									byte[] signed_data = (byte[]) message.getObjContents().get(2);

									String params = gc.decrypt("AES", enc_params, _aesKey);
									// try again if it fails because sometimes weird shit happens
									if (params == null) {
										gc.decrypt("AES", enc_params, _aesKey);
									}
									if (params == null) {
										gc.decrypt("AES", enc_params, _aesKey);
									}
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### LIST GROUP MEMBERS #######################//

				} else if (message.getMessage().equals("LMEMBERS")) // Client wants a list of members in a group
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### ADD USER TO GROUP #######################//

				} else if (message.getMessage().equals("AUSERTOGROUP")) // Client wants to add user to a group
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

					// ####################### REMOVE USER FROM GROUP #######################//

				} else if (message.getMessage().equals("RUSERFROMGROUP")) // Client wants to remove user from a group
				{
					if (message.getObjContents().size() < 4) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(3);
						gc.checkSequence(seq, expseq);
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
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);
				}

				// ####################### GET CURRENT GROUP KEY #######################//

				else if (message.getMessage().equals("GETGKEY")) {
					if (message.getObjContents().size() < 1) {
						response = new Envelope("FAIL");
					} else {
						response = new Envelope("FAIL");
						int seq = (Integer) message.getObjContents().get(1);
						gc.checkSequence(seq, expseq);

						if (message.getObjContents().get(0) != null) {
							byte[] grp_token = (byte[]) message.getObjContents().get(0);

							String group_tkn_str = gc.decrypt("AES", grp_token, _aesKey);
							String[] p_arr = group_tkn_str.split("-");

							String groupName = p_arr[0];
							UserToken yourToken = makeTokenFromString(p_arr[1]);
							String curr_key = getKey(groupName, yourToken);
							if (curr_key != null) {
								response = new Envelope("OK"); // success
								byte[] enc_key = gc.encrypt("AES", curr_key, _aesKey);
								response.addObject(enc_key);
								// TODO: SHOULD PROBABLY ADD SOME SORT OF HMAC W/SHARED KEY2 FOR INTEGRITY
							}
						}
					}
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);
				} else if (message.getMessage().equals("DISCONNECT")) // Client wants to disconnect
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
	private UserToken createToken(String username, String fip, int port) {
		// Check that user exists
		if (my_gs.userList.checkUser(username)) {
			long currTime = System.currentTimeMillis();
			long expTime = currTime + 1200000;
			// Issue a new token with server's name, user's name, user's groups, currtime
			// and exptime
			UserToken yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), currTime,
					expTime, fip, port);
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
					if (my_gs.userList.checkUser(username))
						return true;
					else
						return false;
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
						deleteGroup(deleteOwnedGroup.get(index),
								new Token(my_gs.name, username, deleteOwnedGroup, yourToken.getCREtime(),
										yourToken.getEXPtime(), yourToken.getfsIP(), yourToken.getfsPORT()));
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
		if (my_gs.userList.list.get(username) == null) {
			return false;
		}
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

			// create a per-group key.
			byte[] seed = gc.createLamportSeed();
			// System.out.println("The number of bytes is: " + seed.length);
			if (my_gs.gsList.getSeed(groupName) != null) {
				System.out.println("WARNING: This group seed already exists. That's unexpected.");
			}
			my_gs.gsList.addSeed(groupName, seed);

			// Hash it 1000 times (because it was just created and we're starting at 1000)
			byte[] hashedKey = gc.hashSecretKey(seed, 1000);

			// Store H^1000(seed) and 1000
			my_gs.ghkList.addGroupKey(groupName, 1000, hashedKey);
			System.out.println("The hashed group key has been stored.\n\n");
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

				// remove the per-group seed and hash keys
				my_gs.gsList.removeSeed(groupName);
				my_gs.ghkList.removeGroupKey(groupName);
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

					// get the seed and key info
					Hashtable<Integer, byte[]> curr_key = my_gs.ghkList.getGroupKey(groupName);
					byte[] seed = my_gs.gsList.getSeed(groupName);

					// decrement n, recalculate, and save
					int n = curr_key.keys().nextElement();
					byte[] curr_byte = curr_key.get(n);
					n--;
					byte[] dec_key = gc.hashSecretKey(seed, n);
					my_gs.ghkList.addGroupKey(groupName, n, dec_key);
					System.out.println("The group key has been updated.");
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

	private String getKey(String group, UserToken token) {
		String ckey = new String();
		String requester = token.getSubject();
		if (my_gs.userList.checkUser(requester)) {
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// check to see if the requestor is a member of the group
			if (temp.contains(group)) {
				Hashtable<Integer, byte[]> curr_key;
				curr_key = my_gs.ghkList.getGroupKey(group);

				// turn it into a string for ease of sending
				try {
					String n = new String(Integer.toString(curr_key.keys().nextElement()));
					// need a 1:1 encoding so the number of bytes don't change.
					String key = new String(curr_key.get(Integer.parseInt(n)), "ISO-8859-1");
					ckey = n + "~" + key;
				} catch (Exception e) {
					System.out.println("Error getting group key: " + e);
				}
				return ckey;
			} else {
				System.out.println("User is not a member of the request group and cannot get the key!");
			}
		}
		return null;
	}

	private UserToken makeTokenFromString(String tokenString) {
		// String[] tokenComps = tokenString.split(";");
		// String issuer = tokenComps[0];
		// String subject = tokenComps[1];
		// List<String> groups = new ArrayList<>();
		// for (int i = 2; i < tokenComps.length; i++) {
		// groups.add(tokenComps[i]);
		// }
		// return new Token(issuer, subject, groups);
		return gc.makeTokenFromString(tokenString);

	}
}
