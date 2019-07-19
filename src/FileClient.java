
/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.StringTokenizer;
import java.io.ObjectInputStream;
import javax.crypto.Mac;
import java.security.Signature;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;

public class FileClient extends Client implements FileClientInterface {

	Crypto fc = new Crypto();
	int expseq = 0;

	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0) == '/') {
			remotePath = filename.substring(1);
		} else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); // Success

		// prepare request
		String pubKey = c.toString(groupK);
		String concatted = remotePath + "||" + pubKey + token;

		byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);

		env.addObject(encryptedToken); // Add encrypted token/key
		env.addObject(fsMac); // add signed data
		env.addObject(++expseq);
		++expseq;

		try {
			output.writeObject(env);
			env = (Envelope) input.readObject();
			int seq = (Integer) env.getObjContents().get(0);
			fc.checkSequence(seq, expseq);
			if (env.getMessage().compareTo("OK") == 0) {
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

				Envelope env = new Envelope("DOWNLOADF"); // Success

				// prepare metadata request
				//TODO: Don't send group public key.
				String pubKey = c.toString(groupK);
				String concatted = pubKey + token + "||" + sourceFile;
				byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);

				env.addObject(encryptedToken); // Add encrypted token/key
				env.addObject(fsMac); // add signed data
				env.addObject(++expseq);
				++expseq;
				output.writeObject(env);

				byte[] curr_key = null;

				env = (Envelope) input.readObject();
				if (env.getMessage().equals("READY")) {
					// get file's n for lamport
					int file_n = (Integer) env.getObjContents().get(0);
					int seq = (Integer) env.getObjContents().get(1);
					fc.checkSequence(seq, expseq);

					// with n extracted, get the key
					// subtract my n from the gserver from this n
					int hash_n = file_n - shared_n;
					if(hash_n < 0){
						System.out.println("Requestor has invalid group key. Terminating request...");
						return false;
					}
					else{
						System.out.println("Updating group key...");
						curr_key = fc.hashSecretKey(key, hash_n);
					}

					// make the secret key
					SecretKey skey = fc.makeAESKeyFromString(curr_key);
					//System.out.println("This is the key..." + Base64.getEncoder().encodeToString(skey.getEncoded()));

					// Now get the file chunks
					env = (Envelope) input.readObject();
					while (env.getMessage().compareTo("CHUNK") == 0) {
						// decrypt abnd write
						byte[] decrypted_file = c.aesGroupDecrypt((byte[]) env.getObjContents().get(0), skey);
						fos.write(decrypted_file, 0, (Integer) env.getObjContents().get(1));
						System.out.printf(".");
						env = new Envelope("DOWNLOADF"); // Success
						output.writeObject(env);
						env = (Envelope) input.readObject();
					}
					fos.close();

					if (env.getMessage().compareTo("EOF") == 0) {
						seq = (Integer) env.getObjContents().get(0);
						expseq++;
						fc.checkSequence(seq, expseq);
						fos.close();
						System.out.printf("\nTransfer successful file %s\n", sourceFile);
						env = new Envelope("OK"); // Success
						env.addObject(++expseq);
						++expseq;
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
			Envelope message = null, e = null;

			message = new Envelope("LFILES"); // Success

			// prepare request
			String pubKey = c.toString(groupK);
			String concatted = pubKey + token;

			// Encrypt with shared key
			byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);

			message.addObject(encryptedToken); // Add encrypted token/key
			message.addObject(fsMac); // add signed data
			message.addObject(++expseq);
			++expseq;
			output.writeObject(message);

			e = (Envelope) input.readObject();

			// If server indicates success, return the files list
			if (e.getMessage().equals("OK")) {
				int seq = (Integer) e.getObjContents().get(1);
				fc.checkSequence(seq, expseq);
				byte[] flist = (byte[]) e.getObjContents().get(0);

				if (flist != null) {
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
			message = new Envelope("UPLOADF"); // Success

			//TODO: Don't send group key. It is assumed it is already here.
			// prepare metadata request
			String pubKey = c.toString(groupK);
			String concatted = pubKey + token + "||" + destFile + "||" + group;
			byte[] encryptedToken = c.encrypt("AES", concatted, sharedKey);

			message.addObject(encryptedToken); // Add encrypted token/key
			message.addObject(fsMac); // add signed data
			message.addObject(++expseq);
			++expseq;
			output.writeObject(message);

			FileInputStream fis = new FileInputStream(sourceFile);

			env = (Envelope) input.readObject();

			// If server indicates success, return the member list
			if (env.getMessage().equals("READY")) {
				int seq = (Integer) env.getObjContents().get(0);
				fc.checkSequence(seq, expseq);
				System.out.printf("Meta data upload successful\n");
			} else {
				System.out.printf("Upload failed: %s\n", env.getMessage());
				return false;
			}
			// establish the shared group key for encryption
			SecretKey skey = fc.makeAESKeyFromString(key);
			do {
				byte[] buf = new byte[4096];
				if (env.getMessage().compareTo("READY") != 0) {
					System.out.printf("Server error: %s\n", env.getMessage());
					return false;
				}
				message = new Envelope("CHUNK");
				// read in from the file
				int n = fis.read(buf); // can throw an IOException
				//encrypt the chunk
				byte [] enc_buf = c.aesGroupEncrypt(new String(buf), skey);
				if (n > 0) {
					System.out.printf(".");
				} else if (n < 0) {
					System.out.println("Read error");
					return false;
				}

				// add shared n and encrypted chunk (no need to encrypt further)
				message.addObject(shared_n);
				message.addObject(enc_buf);
				message.addObject(++expseq);
				++expseq;
				message.addObject(enc_buf.length);

				output.writeObject(message);

				env = (Envelope) input.readObject();

			} while (fis.available() > 0);

			// If server indicates success, return the member list
			if (env.getMessage().compareTo("READY") == 0) {
				int seq = (Integer) env.getObjContents().get(0);
				fc.checkSequence(seq, expseq);

				message = new Envelope("EOF");
				message.addObject(++expseq);
				++expseq;
				output.writeObject(message);

				env = (Envelope) input.readObject();
				if (env.getMessage().compareTo("OK") == 0) {
					seq = (Integer) env.getObjContents().get(0);
					fc.checkSequence(seq, expseq);
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
