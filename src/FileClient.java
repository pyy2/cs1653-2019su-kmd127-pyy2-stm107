
/* FileClient provides all the client functionality regarding the file server */
import java.io.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class FileClient extends Client implements FileClientInterface {

	//Crypto fc = new Crypto();
	int expseq = 0;

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0) == '/') {
			remotePath = filename.substring(1);
		} else {
			remotePath = filename;
		}
		Envelope env = new Envelope(new String(c.encrypt("AES", "DELETEF", sharedKey))); // Success

		String concatted = remotePath + "||" + token;

		byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);
		byte[] reqhmac = c.createHmac(encryptedToken);

		env.addObject(encryptedToken); // Add encrypted token/key
		env.addObject(reqhmac); // add signed data
		env.addObject(fsMac); // for token verification
		env.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
		++expseq;

		try {
			output.writeObject(env);
			env = (Envelope) input.readObject();
			byte[] seq = (byte[]) env.getObjContents().get(0);
			c.checkSequence(seq, expseq);
			if (env.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
				System.out.printf("File %s deleted successfully\n", filename);
			} else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}

		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token, int shared_n, byte[] key) {
		if (sourceFile.charAt(0) == '/') {
			sourceFile = sourceFile.substring(1);
		}

		File file = new File(destFile);
		try {

			if (!file.exists()) {
				file.createNewFile();
				FileOutputStream fos = new FileOutputStream(file);

				Envelope env = new Envelope(new String(c.encrypt("AES", "DOWNLOADF", sharedKey))); // Success

				// prepare metadata request
				// TODO: Don't send group public key.
				//String pubKey = c.toString(groupK);
				String concatted = token + "||" + sourceFile;
				byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);
				byte[] reqhmac = c.createHmac(encryptedToken);

				env.addObject(encryptedToken); // Add encrypted token/key
				env.addObject(fsMac); // add signed data
				env.addObject(reqhmac);
				env.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
				++expseq;
				output.writeObject(env);

				byte[] curr_key = null;

				env = (Envelope) input.readObject();
				if (env.getMessage().equals(new String(c.encrypt("AES", "READY", sharedKey)))) {
					// get file's n for lamport
					int file_n = (Integer) env.getObjContents().get(0);
					byte[] seq = (byte[]) env.getObjContents().get(1);
					c.checkSequence(seq, expseq);

					// with n extracted, get the key
					// subtract my n from the gserver from this n
					int hash_n = file_n - shared_n;
					if (hash_n < 0) {
						System.out.println("Requestor has invalid group key. Terminating request...");
						return false;
					} else {
						System.out.println("Updating group key...");
						curr_key = c.hashSecretKey(key, hash_n);
					}

					// make the secret key
					SecretKey skey = c.makeAESKeyFromString(curr_key);
					// System.out.println("This is the key..." +
					// Base64.getEncoder().encodeToString(skey.getEncoded()));

					// Now get the file chunks
					env = (Envelope) input.readObject();
					while (env.getMessage().compareTo(new String(c.encrypt("AES", "CHUNK", sharedKey))) == 0) {
						// decrypt abnd write
						byte[] decrypted_file = c.aesGroupDecrypt((byte[]) env.getObjContents().get(0), skey);
						fos.write(decrypted_file, 0, (Integer) env.getObjContents().get(1));
						System.out.printf(".");
						env = new Envelope(new String(c.encrypt("AES", "DOWNLOADF", sharedKey))); // Success
						output.writeObject(env);
						env = (Envelope) input.readObject();
					}
					fos.close();

					if (env.getMessage().compareTo(new String(c.encrypt("AES", "EOF", sharedKey))) == 0) {
						seq = (byte[]) env.getObjContents().get(0);
						c.checkSequence(seq, ++expseq);
						fos.close();
						System.out.printf("\nTransfer successful file %s\n", sourceFile);
						env = new Envelope(new String(c.encrypt("AES", "OK", sharedKey))); // Success
						env.addObject(c.encrypt("AES", Integer.toString(expseq), sharedKey));
						System.out.println("The seq in the client is: " + expseq);
						//++expseq;
						output.writeObject(env);
					} else {
						System.out.printf("Error reading file %(s (%s)\n", sourceFile, env.getMessage());
						file.delete();
						return false;
					}
				}
			}

			else {
				System.out.printf("Error couldn't create file %s\n", destFile);
				return false;
			}

		} catch (IOException e1) {

			System.out.printf("Error couldn't create file %s\n", destFile);
			return false;

		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
		return true;
	}

	public List<String> listFiles(UserToken token) {
		try {
			//Envelope message = null, e = null;

			Envelope message = new Envelope(new String(c.encrypt("AES", "LFILES", sharedKey))); // Success

			// Encrypt with shared key
			byte[] encryptedToken = c.encrypt("AES", token.toString(), sharedKey);

			message.addObject(encryptedToken); // Add encrypted token/key
			message.addObject(fsMac); // add signed data
			message.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
			++expseq;
			output.writeObject(message);

			Envelope e = (Envelope) input.readObject();

			// If server indicates success, return the files list
			if (e.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
				byte[] seq = (byte[]) e.getObjContents().get(1);
				c.checkSequence(seq, expseq);
				byte[] flist = (byte[]) e.getObjContents().get(0);

				if (flist != null) {
					System.out.println("Are we here??");
					String[] filenames = c.decrypt("AES", flist, sharedKey).split("\\|\\|");
					return Arrays.asList(filenames);
				}
			}
			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean upload(String sourceFile, String destFile, String group, UserToken token, int shared_n, byte[] key) {

		if (destFile.charAt(0) != '/') {
			destFile = "/" + destFile;
		}

		try {
			Envelope message = null, env = null;
			// Tell the server to return the member list
			message = new Envelope(new String(c.encrypt("AES", "UPLOADF", sharedKey))); // Success

			// TODO: Don't send group key. It is assumed it is already here.
			// prepare metadata request
			String pubKey = c.toString(groupK);
			String concatted =  token + "||" + destFile + "||" + group;
			byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);
			byte[] reqhmac = c.createHmac(encryptedToken);

			message.addObject(encryptedToken); // Add encrypted token/key
			message.addObject(reqhmac);
			message.addObject(fsMac); // add signed data
			message.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
			++expseq;
			output.writeObject(message);

			FileInputStream fis = new FileInputStream(sourceFile);

			env = (Envelope) input.readObject();

			if (env.getMessage().equals(new String(c.encrypt("AES", "READY", sharedKey)))) {
				byte[] seq = (byte[]) env.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				System.out.printf("Meta data upload successful\n");
			} else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
			// establish the shared group key for encryption
			SecretKey skey = c.makeAESKeyFromString(key);
			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo(new String(c.encrypt("AES", "READY", sharedKey))) != 0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope(new String(c.encrypt("AES", "CHUNK", sharedKey)));
				// read in from the file
				int n = fis.read(buf); // can throw an IOException
				// encrypt the chunk
				byte[] enc_buf = c.aesGroupEncrypt(new String(buf), skey);
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				// add shared n and encrypted chunk (no need to encrypt further)
				message.addObject(shared_n);
				message.addObject(enc_buf);
				message.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
				++expseq;
				message.addObject(enc_buf.length);

				output.writeObject(message);

				env = (Envelope) input.readObject();

			} while (fis.available() > 0);

			// If server indicates success, return the member list
			if (env.getMessage().compareTo(new String(c.encrypt("AES", "READY", sharedKey))) == 0) {
				byte[] seq = (byte[]) env.getObjContents().get(0);
				c.checkSequence(seq, expseq);

				message = new Envelope(new String(c.encrypt("AES", "EOF", sharedKey)));
				message.addObject(c.aesGroupEncrypt(Integer.toString(++expseq), sharedKey));
				++expseq;
				output.writeObject(message);

				env = (Envelope) input.readObject();
				if (env.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
					seq = (byte[]) env.getObjContents().get(0);
					c.checkSequence(seq, expseq);
					System.out.printf("\nFile data upload successful\n");
				} else {

					System.out.printf("\nUpload failed: %s\n", env.getMessage());
					return false;
				}

			} else {

				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}

		} catch (

		Exception e1) {
			System.err.println("Error: " + e1.getMessage());
			e1.printStackTrace(System.err);
			return false;
		}
		return true;
	}
}
