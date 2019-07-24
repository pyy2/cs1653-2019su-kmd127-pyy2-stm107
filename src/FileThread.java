
/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.io.*;
import java.util.*;
import java.lang.String;
import java.security.*;
import javax.crypto.*;

public class FileThread extends Thread {

	String ip;
	int port;
	private final Socket socket;
	PublicKey pub; // fs public key
	PrivateKey priv; // fs private key
	SecretKey _aesKey; // shared symmetric key b/w client-fs
	PublicKey clientK; // client publickey
	PublicKey gsKey;
	Crypto fc; // filecrypto class
	SecretKey veriK;

	// local sequence # tracker
	int expseq = 1;

	public FileThread(Socket _socket, String _ip, int _port) {
		if (_ip.equals("0.0.0.0") || _ip.equals("localhost")) {
			_ip = "127.0.0.1";
		}
		socket = _socket;
		ip = _ip;
		port = _port;
		fc = new Crypto();
		veriK = null;
	}



	public void run() {
		boolean proceed = true;
		try {

			// ####################### HAND SHAKE PROTOCOL #######################//

			System.out.println("\n*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;

			// sets fileserver keys
			pub = FileServer.pub;
			priv = FileServer.priv;
			gsKey = FileServer.gsKey;

			//System.out.println(fc.RSAtoString(pub));

			System.out.println("\n########### SECURING CLIENT CONNECTION ###########");

			// send FS public key to client
			System.out.println("FS public key -> Client: Sent");
			output.writeObject(pub); // send file public key
			output.flush();

			// get CL public key
			fc.setSysK(input.readObject()); // set client's public key (encoded)
			clientK = fc.getSysK();

			// get pseudo-random number + challenge from client
			String temp = fc.decrypt("RSA/ECB/PKCS1Padding", (byte[]) input.readObject(), priv);
		//	System.out.println(temp);
			String init[] = temp.split("\\|\\|");
			String clRand = init[0];
			String challenge = init[1];
			System.out.println("\nCL Random -> FS: Received");
			System.out.println("\nCL Challenge -> FS: Received");

			// generate FS random #
			fc.setRandom();
			String random = fc.byteToString(fc.getRandom());
			System.out.println("\nFS Random # -> CL: Sent" );
			output.writeObject(fc.encrypt("RSA/ECB/PKCS1Padding", random, clientK));
			output.flush();

			byte[] ka = fc.createChecksum(clRand + random); // SHA256(Ra||Rb)
			byte[] kb = fc.createChecksum(random + clRand); // SHA256(Rb||Ra)
			veriK = fc.makeAESKeyFromString(kb);
			fc.setVeriK(veriK); // set verification key

			fc.setAESKey(fc.byteToString(ka));
			_aesKey = fc.getAESKey();
			System.out.println("\nCL Shared Key Set: Created");
			System.out.println("\nCL Shared Verification Key: Created");

			// verify checksum & signature
			byte[] _checkSum = (byte[]) input.readObject(); // read checksum
			if (fc.isEqual(_checkSum, fc.createChecksum(temp)))
				System.out.println("Checksum Verified");
			else
				socket.close(); // terminate connection

			byte[] signedChecksum = (byte[]) input.readObject(); // signed checksum
			if (!fc.verifySignature(_checkSum, signedChecksum))
				socket.close();

			// respond with challenge
			output.writeObject(challenge);
			output.flush();

			System.out.println("\n########### FS CONNECTION W CLIENT SECURE ###########\n");

			// Globals for encrypted envelope messages
			String encOK = new String(fc.encrypt("AES", "OK", _aesKey));
			String encFAIL = new String(fc.encrypt("AES", "FAIL", _aesKey));
			String encDISCONNECT = new String(fc.encrypt("AES", "DISCONNECT", _aesKey));
			String encREADY = new String(fc.encrypt("AES", "READY", _aesKey));
			String encCHUNK = new String(fc.encrypt("AES", "CHUNK", _aesKey));
			String encEOF = new String(fc.encrypt("AES", "EOF", _aesKey));
			String encLFILES = new String(fc.encrypt("AES", "LFILES", _aesKey));
			String encFAILBADCONTENTS = new String(fc.encrypt("AES", "FAIL-BADCONTENTS", _aesKey));
			String encFAILBADPATH = new String(fc.encrypt("AES", "FAIL-BADPATH", _aesKey));
			String encFAILBADFILE = new String(fc.encrypt("AES", "FAIL-BADFILE", _aesKey));
			String encFAILBADGROUP = new String(fc.encrypt("AES", "FAIL-BADGROUP", _aesKey));
			String encFAILBADHMAC = new String(fc.encrypt("AES", "FAIL-BADHMAC", _aesKey));
			String encFAILBADREQUEST = new String(fc.encrypt("AES", "FAIL-BADREQUEST", _aesKey));
			String encFAILBADFIELDS= new String(fc.encrypt("AES", "FAIL-BADFIELDS", _aesKey));
			String encFAILBADGSIG = new String(fc.encrypt("AES", "FAIL-BADGSSIG", _aesKey));
			String encFAILFILEEXISTS = new String(fc.encrypt("AES", "FAIL-FILEEXISTS", _aesKey));
			String encFAILUNAUTHORIZED = new String(fc.encrypt("AES", "FAIL-UNAUTHORIZED", _aesKey));
			String encERRORTRANSFER = new String(fc.encrypt("AES", "ERROR_TRANSFER", _aesKey));
			String encFILEMISSING = new String(fc.encrypt("AES", "ERROR_FILEMISSING", _aesKey));
			String encPERMISSION = new String(fc.encrypt("AES", "ERROR_PERMISSION", _aesKey));
			String encNOTONDISK = new String(fc.encrypt("AES", "ERROR_NOTONDISK", _aesKey));
			String encDOWNLOADF = new String(fc.encrypt("AES", "DOWNLOADF", _aesKey));
			String encUPLOADF = new String(fc.encrypt("AES", "UPLOADF", _aesKey));
			String encDELETEF = new String(fc.encrypt("AES", "DELETEF", _aesKey));
			String encDOESNTEXIST = new String(fc.encrypt("AES", "ERROR_DOESNTEXIST", _aesKey));
			String encDELETE = new String(fc.encrypt("AES", "ERROR_DELETE", _aesKey));



			do {
				Envelope e = (Envelope) input.readObject();
				response = null;
				System.out.println("Request received: " + e.getMessage());

				// ####################### LIST FILES #######################//

				// Handler to list files that this user is allowed to see
				if (e.getMessage().equals(encLFILES)) {

					byte[] seq = (byte[]) e.getObjContents().get(2);
					fc.checkSequence(seq, expseq);

					if (e.getObjContents().size() < 2) {
						response = new Envelope(encFAILBADCONTENTS);
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope(encFAILBADPATH);
						}
						if (e.getObjContents().get(1) == null) {
							response = new Envelope(encFAILBADGROUP);
						} else {
							// base case
							response = new Envelope(encFAILBADHMAC);
							// get user token||key and signed hmac by gs
							byte[] tok = (byte[]) e.getObjContents().get(0);
							byte[] fsMac = (byte[]) e.getObjContents().get(1);

							// decrypt to get token/key
							String decrypted = fc.decrypt("AES", tok, _aesKey);
							//String[] st = decrypted.split("\\|\\|");
						//	String groupK = st[0];
							String token = decrypted;

							fc.verifyFServer(fc.makeTokenFromString(token), ip, port);

							// make unsigned fsmac for Checking
							byte[] btoken = token.getBytes();
							Mac mac = Mac.getInstance("HmacSHA256", "BC");
							mac.init(clientK);
							mac.update(btoken);
							byte[] out = mac.doFinal();
							//System.out.println("This is the thing from fserver: " + new String(out));
							if (!fc.verifyfsMac(out, fsMac, gsKey)) {
								System.out.println("Signature not consistent.");
							}
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
								response = new Envelope(encOK);
								response.addObject(fc.createEncryptedString(fileList));
						}
					}
					response.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
					++expseq;
					output.writeObject(response);

					// ####################### UPLOAD FILES #######################//

				} else if (e.getMessage().equals(encUPLOADF)) {
					if (e.getObjContents().size() < 4) {
						response = new Envelope(encFAILBADCONTENTS);
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope(encFAILBADREQUEST);
						} else if (e.getObjContents().get(1) == null) {
							response = new Envelope(encFAILBADGROUP);
						} else {
							byte[] seq = (byte[]) e.getObjContents().get(3);
							fc.checkSequence(seq, expseq);
							byte[] reqhmac = (byte[]) e.getObjContents().get(1);
							byte[] req = (byte[]) e.getObjContents().get(0);
							byte[] fsMac = (byte[]) e.getObjContents().get(2);

							// decrypt to get request (gsPK, token, destFile, group)
							String decrypted = fc.decrypt("AES", req, _aesKey);
							String[] st = decrypted.split("\\|\\|");

							// if length doesn't match
							if (st.length != 3) {
								System.out.println(st.length);
								response = new Envelope(encFAILBADFIELDS);
							} else {
								//String groupK = st[0];
								String token = st[0];
								String remotePath = st[1];
								String group = st[2];


								fc.verifyFServer(fc.makeTokenFromString(token), ip, port);

								// Verify the HMAC of the request data
								if (!fc.verifyHmac(req, reqhmac)) {
									System.out.println("HMAC not consistent.");
								}

								// make unsigned fsmac for Checking
								byte[] btoken = token.getBytes();
								Mac mac = Mac.getInstance("HmacSHA256", "BC");
								mac.init(clientK);
								mac.update(btoken);
								byte[] out = mac.doFinal();
								//System.out.println("This is the thing from fserver: " + new String(out));
								if (!fc.verifyfsMac(out, fsMac, gsKey)) {
									System.out.println("Signature not consistent. Token tampering may have occurred.");
								}
								// create hmac from clientk
								// byte[] concatted = (groupK + "||" + token).getBytes();
								// byte[] out = fc.createClientHmac(concatted, fc.getSysK());
								int shared_n = 0;
								// // verify signature is from gs
								// if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
								// 	System.out.println("Signature verification failed");
								// }
								UserToken yourToken = (UserToken) fc.makeTokenFromString(token);

								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope(encFAILFILEEXISTS); // Success
								} else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope(encFAILUNAUTHORIZED); // Success
								} else {
									File file = new File("shared_files/" + remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n",
											remotePath.replace('/', '_'));

									response = new Envelope(encREADY); // Success
									response.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
									++expseq;
									output.writeObject(response);

									e = (Envelope) input.readObject();
									while (e.getMessage().compareTo(encCHUNK) == 0) {
										// Store the file that has been ENCRYPTED WITH THE GROUP KEY
										seq = (byte[]) e.getObjContents().get(2);
										fc.checkSequence(seq, expseq);
										byte[] b = (byte[]) e.getObjContents().get(1);
										shared_n = (Integer) e.getObjContents().get(0);

										// write data to the file.
										fos.write(b);
										response = new Envelope(encREADY); // Success
										response.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
										++expseq;
										output.writeObject(response);
										e = (Envelope) input.readObject();
									}

									// add shared_n as ShareFile metadata
									if (e.getMessage().compareTo(encEOF) == 0) {
										seq = (byte[]) e.getObjContents().get(0);
										fc.checkSequence(seq, expseq);
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath,
												shared_n);
										response = new Envelope(encOK); // Success
									} else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope(encERRORTRANSFER); // Success
									}
									fos.close();
								}
							}
						}
					}
					response.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
					++expseq;
					output.writeObject(response);

					// ####################### DOWNLOAD FILES #######################//

				} else if (e.getMessage().compareTo(encDOWNLOADF) == 0) {

					if (e.getObjContents().size() < 4) {
						response = new Envelope(encFAILBADCONTENTS);
					} else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope(encFAILBADREQUEST);
						}
						if (e.getObjContents().get(1) == null) {
							response = new Envelope(encFAILBADHMAC);
						} else {
							byte[] seq = (byte[]) e.getObjContents().get(3);
							fc.checkSequence(seq, expseq);
							byte[] req = (byte[]) e.getObjContents().get(0);
							byte[] fsMac = (byte[]) e.getObjContents().get(1);
							byte[] sigHmac = (byte[]) e.getObjContents().get(2);

							// decrypt to get request (gsPK, token, destFile, group)
							String decrypted = fc.decrypt("AES", req, _aesKey);
							String[] st = decrypted.split("\\|\\|");

							if (st.length != 2) {
								response = new Envelope(encFAILBADFIELDS);
							} else {
								//String groupK = st[0];
								String token = st[0];
								String remotePath = st[1];

								fc.verifyFServer(fc.makeTokenFromString(token), ip, port);

								// Verify the HMAC of the request data
								if (!fc.verifyHmac(req, sigHmac)) {
									System.out.println("HMAC not consistent.");
								}
								// create hmac from clientk
								// byte[] concatted = (groupK + "||" + token).getBytes();
								// byte[] out = fc.createClientHmac(concatted, fc.getSysK());
								//
								// // verify signature is from gs
								// if (!fc.verifySignature(out, sigHmac, fc.stringToPK(groupK))) {
								// 	response = new Envelope(encFAILBADGSIG);

								// make unsigned fsmac for Checking
								byte[] btoken = token.getBytes();
								Mac mac = Mac.getInstance("HmacSHA256", "BC");
								mac.init(clientK);
								mac.update(btoken);
								byte[] out = mac.doFinal();
								//System.out.println("This is the thing from fserver: " + new String(out));
								if (!fc.verifyfsMac(out, fsMac, gsKey)) {
									System.out.println("Signature not consistent. Token tampering may have occurred.");
								}

									UserToken t = (UserToken) fc.makeTokenFromString(token);
									ShareFile sf = FileServer.fileList.getFile("/" + remotePath);

									if (sf == null) {
										System.out.printf("Error: File %s doesn't exist\n", remotePath);
										response = new Envelope(encFILEMISSING);
									} else if (!t.getGroups().contains(sf.getGroup())) {
										System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
										response = new Envelope(encPERMISSION);
									} else {
										int shared_n = sf.getN();
										try {
											File f = new File("shared_files/_" + remotePath.replace('/', '_'));
											if (!f.exists()) {
												System.out.printf("Error file %s missing from disk\n",
														"_" + remotePath.replace('/', '_'));
												response = new Envelope(encNOTONDISK);
											} else {
												FileInputStream fis = new FileInputStream(f);

												response = new Envelope(encREADY); // Success
												// Send shared n over to client for key generation.
												response.addObject(shared_n);
												response.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
												output.writeObject(response);
												++expseq;

												do {
													byte[] buf = new byte[4096];
													if (e.getMessage().compareTo(encDOWNLOADF) != 0) {
														System.out.printf("Server error: %s\n", e.getMessage());
														break;
													}
													e = new Envelope(encCHUNK);
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

												if (e.getMessage().compareTo(encDOWNLOADF) == 0) {
													e = new Envelope(encEOF);
													e.addObject(fc.aesGroupEncrypt(Integer.toString(expseq), _aesKey));

													output.writeObject(e);

													e = (Envelope) input.readObject();

													if (e.getMessage().compareTo(encOK) == 0) {
														seq = (byte[]) e.getObjContents().get(0);
														System.out.printf("File data download successful\n");
													} else {

														System.out.printf("Download failed: %s\n", e.getMessage());

													}

												} else {

													System.out.printf("Download failed: %s\n", e.getMessage());

												}
												fis.close();
											}
										} catch (Exception e1) {
											System.err.println("Error: " + e1.getMessage());
											response = new Envelope(encFAILBADFILE);
											// e1.printStackTrace(System.err);
										}
									}

							}
						}
					}
					output.writeObject(response);


					// ####################### DELETE FILES #######################//

				} else if (e.getMessage().compareTo(encDELETEF) == 0) {

					byte[] tok = (byte[]) e.getObjContents().get(0);
					byte[] sigHmac = (byte[]) e.getObjContents().get(1);
					byte[] fsMac = (byte []) e.getObjContents().get(2);
					byte[] seq = (byte[]) e.getObjContents().get(3);
					fc.checkSequence(seq, expseq);

					// decrypt to get token/key
					String decrypted = fc.decrypt("AES", tok, _aesKey);
					String[] st = decrypted.split("\\|\\|");
					String remotePath = st[0];
					String token = st[1];
				  //System.out.println("This is the token: " + token);

					fc.verifyFServer(fc.makeTokenFromString(token), ip, port);

					// Verify the HMAC of the request data
					if (!fc.verifyHmac(tok, sigHmac)) {
						System.out.println("HMAC not consistent.");
					}

					// make unsigned fsmac for Checking
					byte[] btoken = token.getBytes();
					Mac mac = Mac.getInstance("HmacSHA256", "BC");
					mac.init(clientK);
					mac.update(btoken);
					byte[] out = mac.doFinal();
					//System.out.println("This is the thing from fserver: " + new String(out));
					if (!fc.verifyfsMac(out, fsMac, gsKey)) {
						System.out.println("Signature not consistent. Token tampering may have occurred.");
					}
					UserToken t = (UserToken) fc.makeTokenFromString(token);


					ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
					if (sf == null) {
						System.out.printf("Error: File %s doesn't exist\n", remotePath);
						e = new Envelope(encDOESNTEXIST);
					} else if (!t.getGroups().contains(sf.getGroup())) {
						System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
						e = new Envelope(encPERMISSION);
					} else {

						try {

							File f = new File("shared_files/" + "_" + remotePath.replace('/', '_'));

							if (!f.exists()) {
								System.out.printf("Error file %s missing from disk\n",
										"_" + remotePath.replace('/', '_'));
								e = new Envelope(encFILEMISSING);
							} else if (f.delete()) {
								System.out.printf("File %s deleted from disk\n", "_" + remotePath.replace('/', '_'));
								FileServer.fileList.removeFile("/" + remotePath);
								e = new Envelope(encOK);
							} else {
								System.out.printf("Error deleting file %s from disk\n",
										"_" + remotePath.replace('/', '_'));
								e = new Envelope(encDELETE);
							}

						} catch (Exception e1) {
							System.err.println("Error: " + e1.getMessage());
							e1.printStackTrace(System.err);
							e = new Envelope(e1.getMessage());
						}
					}
					e.addObject(fc.aesGroupEncrypt(Integer.toString(++expseq), _aesKey));
					++expseq;
					output.writeObject(e);

				} else if (e.getMessage().equals(encDISCONNECT)) {
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
