
/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.util.Arrays;
import java.io.ObjectInputStream;
import javax.crypto.Mac;
import java.security.Signature;
import java.security.Security;
import java.util.Base64;

public class GroupClient extends Client implements GroupClientInterface {

	// local sequence # tracker
	int expseq = 0;

	public UserToken getToken(String username) {
		try {
			UserToken token = null;
			Envelope message = null, response = null;

			// Tell the server to return a token.
			message = new Envelope("GET");
			// ecnrypt username with symmetric keys
			byte[] uname = c.encrypt("AES", username, sharedKey);

			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);

			++expseq;

			// Get the response from the server
			response = (Envelope) input.readObject();

			// Successful response
			if (response.getMessage().equals("OK")) {
				// If there is a token in the Envelope, return it
				ArrayList<Object> temp = null;
				temp = response.getObjContents();

				if (temp.size() < 4) {
					System.out.println("Something went wrong!");
					System.out.println("Missing authentication or encryption data!\n\n");
					return null;
				} else {

					int seq = (Integer) response.getObjContents().get(3);
					c.checkSequence(seq, expseq);

					// decrypt and Verify
					byte[] encryptedToken = (byte[]) response.getObjContents().get(0);
					byte[] out = (byte[]) response.getObjContents().get(1);

					// when requesting a "GET" request, create an HMAC instance in case client
					// wants to send to FS [HMAC(Kc, Kg || Token)]Kg-1
					fsMac = (byte[]) response.getObjContents().get(2);

					// get the token concated with the public key
					String tokenAndKey = c.decrypt("AES", encryptedToken, sharedKey);
					// System.out.println("This is the key + token data: " + tokenAndKey);
					// Remove the public group key to get the token info
					String gPubKey = Base64.getEncoder().encodeToString(groupK.getEncoded());
					String tokenString = tokenAndKey.replace(gPubKey, "");
					UserToken sessionToken = makeTokenFromString(tokenString);
					// System.out.println("This is the stringified token data: " + tokenString);

					return sessionToken;

				}
			}

			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}

	}

	public String getKeys(String group, UserToken token){
		try {
			Envelope message = null, response = null;
			message = new Envelope("GETGKEY");

			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(group);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);

			message.addObject(reqBytes);
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();

			// If server indicates success, return the member list
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(1);
				c.checkSequence(seq, expseq);
				byte[] enc_keys = (byte[]) response.getObjContents().get(0);
				String keys = c.decrypt("AES", enc_keys, sharedKey);
				return keys;
			}

			return null;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}
	public boolean lockUser(String username){
		try {
			Envelope message = null, response = null;
			message = new Envelope("LOCK");
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);

			++expseq;

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean unlockUser(String username){
		try {
			Envelope message = null, response = null;
			message = new Envelope("UNLOCK");
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}
			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean userExists(String username) {
		return (getToken(username) != null);
	}

	public boolean checkPassword(String username, String password) {
		try {
			Envelope message = null, response = null;
			message = new Envelope("CPWD");
			// concat username and Password
			String upwd_str = username + ";" + password;
			// encrypt username and password with symmetric key

			byte[] upwd = c.encrypt("AES", upwd_str, sharedKey);
			message.addObject(upwd); // Add user name string
			message.addObject(++expseq);
			System.out.println(expseq);
			output.writeObject(message);
			expseq++;
			System.out.println(expseq);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("Are we getting here??");
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean firstLogin(String username) {
		try {
			Envelope message = null, response = null;
			message = new Envelope("FLOGIN");
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			//System.out.println(expseq);
			output.writeObject(message);
			++expseq;
		//	System.out.println(expseq);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				System.out.println("CHECKING FLOGIN IN THE CLIENT");
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}
			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean resetPassword(String username, String password) {
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Envelope message = null, response = null;
			message = new Envelope("RPASS");
			String upwd_str = username + ";" + password;
			// encrypt username and password with symmetric key
			byte[] upwd = c.encrypt("AES", upwd_str, sharedKey);

			// Add HMAC(Username||password, sharedKey) signed with private key so we know it
			// hasn't been tampered with!
		//	byte[] verify = (username + password).getBytes();
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(sharedKey);
			mac.update(upwd);
			byte[] out = mac.doFinal();
			byte[] signed_data = c.signChecksum(out);

			message.addObject(upwd);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			++expseq;

			output.writeObject(message);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createUser(String username, String password, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to create a user
			message = new Envelope("CUSER");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(username);
			reqParams.add(password);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			++expseq;
			output.writeObject(message);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUser(String username, UserToken token) {
		try {
			Envelope message = null, response = null;

			// Tell the server to delete a user
			message = new Envelope("DUSER");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(username);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			++expseq;
			output.writeObject(message);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean createGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to create a group
			message = new Envelope("CGROUP");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(groupname);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteGroup(String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to delete a group
			message = new Envelope("DGROUP");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(groupname);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	@SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to return the member list
			message = new Envelope("LMEMBERS");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(group);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			++expseq;
			output.writeObject(message);

			response = (Envelope) input.readObject();

			// If server indicates success, return the member list
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(1);
				c.checkSequence(seq, expseq);
				byte[] enc_memList = (byte[]) response.getObjContents().get(0);
				String members = c.decrypt("AES", enc_memList, sharedKey);
				String[] m_arr = members.split("-");
				List<String> memList = new ArrayList<>();
				for (int i = 0; i < m_arr.length; i++) {
					memList.add(m_arr[i]);
				}
				return memList; // This cast creates compiler warnings. Sorry.
			}

			return null;

		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
	}

	public boolean addUserToGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to add a user to the group
			message = new Envelope("AUSERTOGROUP");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(username);
			reqParams.add(groupname);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
	}

	public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
		try {
			Envelope message = null, response = null;
			// Tell the server to remove a user from the group
			message = new Envelope("RUSERFROMGROUP");
			ArrayList<String> reqParams = new ArrayList<>();
			reqParams.add(username);
			reqParams.add(groupname);
			reqParams.add(token.toString());
			byte[] reqBytes = c.createEncryptedString(reqParams);
			byte[] out = c.createHmac(reqBytes);
			byte[] signed_data = c.signChecksum(out);

			message.addObject(reqBytes);
			message.addObject(out);
			message.addObject(signed_data);
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();
			// If server indicates success, return true
			if (response.getMessage().equals("OK")) {
				int seq = (Integer) response.getObjContents().get(0);
				c.checkSequence(seq, expseq);
				return true;
			}

			return false;
		} catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
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
