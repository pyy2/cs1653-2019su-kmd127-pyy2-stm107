
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.util.ArrayList;
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
	SecretKey sharedKey; // shared symmetric key b/w client-fs
	PublicKey clientK; // client publickey
	Crypto fc; // filecrypto class

	public FileThread(Socket _socket) {
		socket = _socket;
		fc = new Crypto();
	}

	public void run() {
		boolean proceed = true;
		try {
			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			final String path = "./FSpublic.key";
			final String path2 = "./FSprivate.key";
			File f1 = new File(path);
			File f2 = new File(path2);

			// if key files don't exist, something went wrong on initialization, ABORT
			if (!f1.exists() && !f2.exists()) {
				System.out.println("FATAL ERROR: FS key NOT found!\n System Exiting");
				System.exit(1);
			}

			// set keys
			if (f1.exists() && f2.exists()) {
				System.out.println("Setting FS public/private keys\n");
				fc.setPublicKey("FS");
				fc.setPrivateKey("FS");
				pub = fc.getPublic();
				priv = fc.getPrivate();
			}
			System.out.println(fc.RSAtoString(pub));

			System.out.println("\n########### SECURING CLIENT CONNECTION ###########");

			System.out.println("FS public key -> Client:\n" + fc.RSAtoString(pub));
			output.writeObject(pub); // send file public key
			output.flush();

			fc.setSysK(input.readObject()); // set client's public key (encoded)
			clientK = fc.getSysK();
			System.out.println("Received client's public key: \n" + fc.RSAtoString(clientK));

			// get aes key + challenge
			String s = fc.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv); // AES
			String _aesKey = s.substring(0, s.lastIndexOf("-"));
			String challenge = s.substring(_aesKey.length(), s.length());
			System.out.println("AESKey: " + _aesKey);
			System.out.println("Challenge: " + challenge);
			fc.setAESKey(_aesKey); // set aes key
			sharedKey = fc.getAESKey();

			// verify checksum
			byte[] _checkSum = (byte[]) input.readObject(); // read checksum
			System.out.println("Client checksum:\n" + fc.toString(_checkSum)); // print
			System.out.println("Checksum verified -> " + fc.isEqual(_checkSum, fc.createChecksum(s)));

			// verify signature
			byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum
			System.out.println("Signed Checksum:\n" + fc.toString(signedChecksum));

			// respond with challenge
			output.writeObject(challenge);

			System.out.println("\n########### FS CONNECTION W CLIENT SECURE ###########\n");

			do {
				Envelope e = (Envelope) input.readObject();
				System.out.println("Request received: " + e.getMessage());

				// Handler to list files that this user is allowed to see
				if (e.getMessage().equals("LFILES")) {
					UserToken yourToken = (UserToken) e.getObjContents().get(0); // Extract token NOTE: This only takes
																					// 1 param, the user token.
					List<String> groups = yourToken.getGroups(); // get associated groups

					List<ShareFile> sfiles = FileServer.fileList.getFiles();
					List<String> fileList = new ArrayList<String>();

					for (ShareFile sf : sfiles) {
						if (groups.contains(sf.getGroup())) {
							fileList.add(sf.getPath());
						}
					}

					// JUST FOR CLIENT TESTING
					response = new Envelope("OK");
					// String test = "THIS IS A TEST";
					// List<String> testList = new ArrayList<String>();
					// testList.add(test);
					response.addObject(fileList);
					output.writeObject(response);

				}
				if (e.getMessage().equals("UPLOADF")) {

					if (e.getObjContents().size() < 3) {
						response = new Envelope("FAIL-BADCONTENTS");
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if (e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if (e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						} else {
							String remotePath = (String) e.getObjContents().get(0);
							String group = (String) e.getObjContents().get(1);
							UserToken yourToken = (UserToken) e.getObjContents().get(2); // Extract token

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
								System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

								response = new Envelope("READY"); // Success
								output.writeObject(response);

								e = (Envelope) input.readObject();
								while (e.getMessage().compareTo("CHUNK") == 0) {
									fos.write((byte[]) e.getObjContents().get(0), 0,
											(Integer) e.getObjContents().get(1));
									response = new Envelope("READY"); // Success
									output.writeObject(response);
									e = (Envelope) input.readObject();
								}

								if (e.getMessage().compareTo("EOF") == 0) {
									System.out.printf("Transfer successful file %s\n", remotePath);
									FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
									response = new Envelope("OK"); // Success
								} else {
									System.out.printf("Error reading file %s from client\n", remotePath);
									response = new Envelope("ERROR-TRANSFER"); // Success
								}
								fos.close();
							}
						}
					}

					output.writeObject(response);
				} else if (e.getMessage().compareTo("DOWNLOADF") == 0) {

					String remotePath = (String) e.getObjContents().get(0);
					Token t = (Token) e.getObjContents().get(1);
					ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope("ERROR_FILEMISSING");
						output.writeObject(e);

					} else if (!t.getGroups().contains(sf.getGroup())) {
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope("ERROR_PERMISSION");
						output.writeObject(e);
					} else {

						try {
							File f = new File("shared_files/_" + remotePath.replace('/', '_'));
							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n",
										"_" + remotePath.replace('/', '_'));
								e = new Envelope("ERROR_NOTONDISK");
								output.writeObject(e);

							} else {
								FileInputStream fis = new FileInputStream(f);

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

									e.addObject(buf);
									e.addObject(new Integer(n));

									output.writeObject(e);

									e = (Envelope) input.readObject();

								} while (fis.available() > 0);

								// If server indicates success, return the member list
								if (e.getMessage().compareTo("DOWNLOADF") == 0) {

									e = new Envelope("EOF");
									output.writeObject(e);

									e = (Envelope) input.readObject();
									if (e.getMessage().compareTo("OK") == 0) {
										System.out.printf("File data upload successful\n");
									} else {

										System.out.printf("Upload failed: %s\n", e.getMessage());

									}

								} else {

									System.out.printf("Upload failed: %s\n", e.getMessage());

								}
							}
						} catch (Exception e1) {
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
				} else if (e.getMessage().compareTo("DELETEF") == 0) {

					String remotePath = (String) e.getObjContents().get(0);
					Token t = (Token) e.getObjContents().get(1);
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
					output.writeObject(e);

				} else if (e.getMessage().equals("DISCONNECT")) {
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
