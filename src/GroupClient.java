
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

	public UserToken getToken(String username, String fip, int fport) {
		try {
			//System.out.println("Client: GET");
			Envelope message = null, response = null;
			ArrayList<String> params = new ArrayList<String>();
			params.add(username);
			params.add(fip);
			params.add(Integer.toString(fport));
			byte[] enc_params = c.createEncryptedString(params);

			//message = new Envelope("GET");
			message = new Envelope(new String(c.encrypt("AES", "GET", sharedKey)));
			message.addObject(enc_params); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);

			++expseq;

			// Get the response from the server
			response = (Envelope) input.readObject();
			System.out.println("Response received: " + response.getMessage());
			if (response.getMessage().equals(c.encrypt("AES", "LOCKED", sharedKey))) {
				System.out.println("The user is locked!");
				System.out.println("Please contact your administrator to unlock.");
				return null;
			}
			// Successful response
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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

	public String getKeys(String group, UserToken token) {
		try {
			System.out.println("GETGKEY");
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "GETGKEY", sharedKey)));

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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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

	public boolean lockUser(String username) {
		try {
			System.out.println("LOCK");
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "LOCK", sharedKey)));
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);

			++expseq;

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
				return true;
			}

			return false;
		} catch (Exception e) {
			return false;
		}
	}

	public boolean unlockUser(String username) {
		try {
			System.out.println("UNLOCK");
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "UNLOCK", sharedKey)));
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);
			++expseq;

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
				return true;
			}
			return false;
		} catch (Exception e) {
			return false;
		}
	}

	public boolean userExists(String username, String fip, int fport) {
		return (getToken(username, fip, fport) != null);
	}

	public boolean checkPassword(String username, String password) {
		try {
			System.out.println("CPWD");
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "CPWD", sharedKey)));
			// concat username and Password
			String upwd_str = username + ";" + password;
			// encrypt username and password with symmetric key

			byte[] upwd = c.encrypt("AES", upwd_str, sharedKey);
			message.addObject(upwd); // Add user name string
			message.addObject(++expseq);
			output.writeObject(message);
			expseq++;

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			System.out.println("FLOGIN");
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "FLOGIN", sharedKey)));
			byte[] uname = c.encrypt("AES", username, sharedKey);
			message.addObject(uname); // Add user name string
			message.addObject(++expseq);
			// System.out.println(expseq);
			output.writeObject(message);
			++expseq;
			// System.out.println(expseq);

			response = (Envelope) input.readObject();

			// If server indicates success, return true
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			System.out.println("RPASS");
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			Envelope message = null, response = null;
			message = new Envelope(new String(c.encrypt("AES", "RPASS", sharedKey)));
			String upwd_str = username + ";" + password;
			// encrypt username and password with symmetric key
			byte[] upwd = c.encrypt("AES", upwd_str, sharedKey);

			// Add HMAC(Username||password, sharedKey) signed with private key so we know it
			// hasn't been tampered with!
			Mac mac = Mac.getInstance("HmacSHA256", "BC");
			mac.init(veriK);
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "CUSER", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "DUSER", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "CGROUP", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "DGROUP", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "LMEMBERS", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "AUSERTOGROUP", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
			message = new Envelope(new String(c.encrypt("AES", "RUSERFROMGROUP", sharedKey)));
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
			if (response.getMessage().equals(new String(c.encrypt("AES", "OK", sharedKey)))) {
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
		return c.makeTokenFromString(tokenString);
	}
}
