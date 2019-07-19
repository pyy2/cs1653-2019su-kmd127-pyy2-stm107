
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.util.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.String;

// security packages
import java.security.*;
import javax.crypto.*;
import java.security.Signature;

public class FileThread extends Thread {
	private final Socket socket;
	PublicKey pub; // fs public key
	PrivateKey priv; // fs private key
	SecretKey _aesKey; // shared symmetric key b/w client-fs
	PublicKey clientK; // client publickey
	Crypto fc; // filecrypto class

	// local sequence # tracker
	int expseq = 1;

	public FileThread(Socket _socket) {
		socket = _socket;
		fc = new Crypto();
	}

	public void run() {
		boolean proceed = true;
		try {

//####################### HAND SHAKE PROTOCOL #######################//

			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			pub = FileServer.pub;
			priv = FileServer.priv;

			System.out.println(fc.RSAtoString(pub));

			System.out.println("\n########### SECURING CLIENT CONNECTION ###########");

			// System.out.println("FS public key -> Client:\n" + fc.RSAtoString(pub));
			output.writeObject(pub); // send file public key
			output.flush();

			fc.setSysK(input.readObject()); // set client's public key (encoded)
			clientK = fc.getSysK();

			// get aes key + challenge
			String s = fc.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv); // AES
			String aesKey = s.substring(0, s.lastIndexOf("-"));
			String challenge = s.substring(aesKey.length(), s.length());
			fc.setAESKey(aesKey); // set aes key
			_aesKey = fc.getAESKey();

			// verify checksum
			byte[] _checkSum = (byte[]) input.readObject(); // read checksum

			// verify signature
			byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum

			// respond with challenge
			output.writeObject(challenge);

			System.out.println("\n########### FS CONNECTION W CLIENT SECURE ###########\n");

			do {
				Envelope e = (Envelope) input.readObject();
				response = null;
				System.out.println("Request received: " + e.getMessage());

//####################### LIST FILES #######################//

				// Handler to list files that this user is allowed to see
				if (e.getMessage().equals("LFILES")) {

					int seq = (Integer) e.getObjContents().get(2);
					fc.checkSequence(seq, expseq);

					if (e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if (e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						} else {
							// base case
							response = new Envelope("FAIL-BADHMAC");
							// get user token||key and signed hmac by gs
							byte[] tokKey = (byte[]) e.getObjContents().get(0);
							byte[] sigHmac = (byte[]) e.getObjContents().get(1);

							// decrypt to get token/key
							String decrypted = fc.decrypt("AES", tokKey, _aesKey);
							String[] st = decrypted.split("\\|\\|");
							String groupK = st[0];
							String token = st[1];

							// create hmac using client's publickey
							byte[] out = fc.createClientHmac(decrypted.getBytes(), fc.getSysK());

							// verify groupkey signature
							if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
								response = new Envelope("FAIL-BADHMAC");
							} else {
								UserToken yourToken = (UserToken) fc.makeTokenFromString(token);

								List<String> groups = yourToken.getGroups(); // get associated groups
								List<ShareFile> sfiles = FileServer.fileList.getFiles();
								ArrayList<String> fileList = new ArrayList<String>();

								for (ShareFile sf : sfiles) {
									if (groups.contains(sf.getGroup())) {
										fileList.add(sf.getPath());
									}
								}

								// return encrypted arraylist
								response = new Envelope("OK");
								response.addObject(fc.createEncryptedString(fileList));
							}
						}
					}
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

//####################### UPLOAD FILES #######################//

				} else if (e.getMessage().equals("UPLOADF")) {
					if (e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADREQUEST");
						} else if (e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						} else {
							int seq = (Integer) e.getObjContents().get(2);
							fc.checkSequence(seq, expseq);
							byte[] req = (byte[]) e.getObjContents().get(0);
							byte[] sigHmac = (byte[]) e.getObjContents().get(1);

							// decrypt to get request (gsPK, token, destFile, group)
							String decrypted = fc.decrypt("AES", req, _aesKey);
							String[] st = decrypted.split("\\|\\|");

							// if length doesn't match
							if (st.length != 4) {
								response = new Envelope("FAIL-BADFIELDS");
							} else {
								String groupK = st[0];
								String token = st[1];
								String remotePath = st[2];
								String group = st[3];

								// create hmac from clientk
								byte[] concatted = (groupK + "||" + token).getBytes();
								byte[] out = fc.createClientHmac(concatted, fc.getSysK());
								int shared_n = 0;
								// verify signature is from gs
								if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
									response = new Envelope("FAIL-BADGSSIG");
								} else {
									UserToken yourToken = (UserToken) fc.makeTokenFromString(token);

									if (FileServer.fileList.checkFile(remotePath)) {
										System.out.printf("Error: file already exists at %s\n", remotePath);
										response = new Envelope("FAIL-FILEEXISTS"); // Success
									} else if (!yourToken.getGroups().contains(group)) {
										System.out.printf("Error: user missing valid token for group %s\n", group);
										response = new Envelope("FAIL-UNAUTHORIZED"); // Success
									} else {
										File file = new File("shared_files/" + remotePath.replace('/', '_'));
										file.createNewFile();
										FileOutputStream fos = new FileOutputStream(file);
										System.out.printf("Successfully created file %s\n",
												remotePath.replace('/', '_'));

										response = new Envelope("READY"); // Success
										response.addObject(++expseq);
										++expseq;
										output.writeObject(response);

										e = (Envelope) input.readObject();
										while (e.getMessage().compareTo("CHUNK") == 0) {
											// Store the file that has been ENCRYPTED WITH THE GROUP KEY
											seq = (Integer)e.getObjContents().get(2);
											fc.checkSequence(seq, expseq);
											byte[] b = (byte[]) e.getObjContents().get(1);
											shared_n = (Integer)e.getObjContents().get(0);

											// write data to the file.
											fos.write(b);
											response = new Envelope("READY"); // Success
											response.addObject(++expseq);
											++expseq;
											output.writeObject(response);
											e = (Envelope) input.readObject();
										}

										// add shared_n as ShareFile metadata
										if (e.getMessage().compareTo("EOF") == 0) {
											seq = (Integer) e.getObjContents().get(0);
											fc.checkSequence(seq, expseq);
											System.out.printf("Transfer successful file %s\n", remotePath);
											FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, shared_n);
											response = new Envelope("OK"); // Success
										} else {
											System.out.printf("Error reading file %s from client\n", remotePath);
											response = new Envelope("ERROR-TRANSFER"); // Success
										}
										fos.close();
									}
								}
							}
						}
					}
					response.addObject(++expseq);
					++expseq;
					output.writeObject(response);

//####################### DOWNLOAD FILES #######################//


				} else if (e.getMessage().compareTo("DOWNLOADF") == 0) {

					if (e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADREQUEST");
						}
						if (e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADHMAC");
						} else {
							int seq = (Integer) e.getObjContents().get(2);
							fc.checkSequence(seq, expseq);
							byte[] req = (byte[]) e.getObjContents().get(0);
							byte[] sigHmac = (byte[]) e.getObjContents().get(1);

							// decrypt to get request (gsPK, token, destFile, group)
							String decrypted = fc.decrypt("AES", req, _aesKey);
							String[] st = decrypted.split("\\|\\|");

							if (st.length != 3) {
								response = new Envelope("FAIL-BADFIELDS");
							} else {
								String groupK = st[0];
								String token = st[1];
								String remotePath = st[2];

								// create hmac from clientk
								byte[] concatted = (groupK + "||" + token).getBytes();
								byte[] out = fc.createClientHmac(concatted, fc.getSysK());

								// verify signature is from gs
								if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
									response = new Envelope("FAIL-BADGSSIG");
								} else {

									UserToken t = (UserToken) fc.makeTokenFromString(token);
									ShareFile sf = FileServer.fileList.getFile("/" + remotePath);

									if (sf == null) {
										System.out.printf("Error: File %s doesn't exist\n", remotePath);
										response = new Envelope("ERROR_FILEMISSING");
									} else if (!t.getGroups().contains(sf.getGroup())) {
										System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
										response = new Envelope("ERROR_PERMISSION");
									} else {
										int shared_n = sf.getN();
										try {
											File f = new File("shared_files/_" + remotePath.replace('/', '_'));
											if (!f.exists()) {
												System.out.printf("Error file %s missing from disk\n",
														"_" + remotePath.replace('/', '_'));
												response = new Envelope("ERROR_NOTONDISK");
											} else {
												FileInputStream fis = new FileInputStream(f);

												response = new Envelope("READY"); // Success
												// Send shared n over to client for key generation.
												response.addObject(shared_n);
												response.addObject(++expseq);
												output.writeObject(response);
												++expseq;

												do {
													byte[] buf = new byte[4096];
													if (e.getMessage().compareTo("DOWNLOADF") != 0) {
														System.out.printf("Server error: %s\n", e.getMessage());
														break;
													}
													e = new Envelope("CHUNK");
													int n = fis.read(buf); // can throw an IOException
													if (n > 0) {
														System.out.printf(".");
													} else if (n < 0) {
														System.out.println("Read error");

													}
													// buffer is already encrypted
													e.addObject(buf);
													e.addObject(new Integer(n));

													output.writeObject(e);

													e = (Envelope) input.readObject();

												} while (fis.available() > 0);

												if (e.getMessage().compareTo("DOWNLOADF") == 0) {
													e = new Envelope("EOF");
													e.addObject(expseq);
													//expseq;
													output.writeObject(e);

													e = (Envelope) input.readObject();

													if (e.getMessage().compareTo("OK") == 0) {
														seq = (Integer) e.getObjContents().get(0);
														fc.checkSequence(seq, expseq);
														System.out.printf("File data download successful\n");
													} else {

														System.out.printf("Download failed: %s\n", e.getMessage());

													}

												} else {

													System.out.printf("Download failed: %s\n", e.getMessage());

												}
											}
										} catch (Exception e1) {
											System.err.println("Error: " + e1.getMessage());
											response = new Envelope("FAIL-BADFILE");
											// e1.printStackTrace(System.err);
										}
									}
								}
							}
						}
					}
					output.writeObject(response);

//####################### DELETE FILES #######################//

				} else if (e.getMessage().compareTo("DELETEF") == 0) {

					byte[] tokKey = (byte[]) e.getObjContents().get(0);
					byte[] sigHmac = (byte[]) e.getObjContents().get(1);
					int seq = (Integer) e.getObjContents().get(2);
					fc.checkSequence(seq, expseq);

					// decrypt to get token/key
					String decrypted = fc.decrypt("AES", tokKey, _aesKey);
					String[] st = decrypted.split("\\|\\|");
					String remotePath = st[0];
					String groupK = st[1];
					String token = st[2];

					// verify signed HMAC created from client's public key of token + key
					// signed by group client
					byte[] concatted = (remotePath + "||" + groupK + "||" + token).getBytes();
					byte[] out = fc.createClientHmac(concatted, fc.getSysK());
					if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
						System.out.println("HMAC not consistent.");
						//output.writeObject(new Envelope("FAIL-BADHMAC"));
						//return;
					}
					UserToken t = (UserToken) fc.makeTokenFromString(token);

					ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_DOESNTEXIST");
					} else if (!t.getGroups().contains(sf.getGroup())) {
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
					} else {

						try {

							File f = new File("shared_files/" + "_" + remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n",
										"_" + remotePath.replace('/', '_'));
								e = new Envelope("ERROR_FILEMISSING");
							} else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_" + remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/" + remotePath);
								e = new Envelope("OK");
							} else {
								System.out.printf("Error deleting file %s from disk\n",
										"_" + remotePath.replace('/', '_'));
								e = new Envelope("ERROR_DELETE");
							}

						} catch (Exception e1) {
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					e.addObject(++expseq);
					++expseq;
					output.writeObject(e);

				} else if (e.getMessage().equals("DISCONNECT-")) {
					socket.close();
					proceed = false;
				}
			} while (proceed);
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}

}
