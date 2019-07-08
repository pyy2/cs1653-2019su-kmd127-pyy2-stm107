/* This list represents the users on the server */
import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;


	public class UserList implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = 7600343803563417992L;
		// changed to protected in oreder to be able to check all users' groups.
		// adding byte array for password hash.
		protected Hashtable<String, User> list = new Hashtable<String, User>();
		protected Set<String> groupSet = new HashSet<String>();

		// used a set to ensure no dupes returns false if group already exists
		public synchronized boolean createGroup(String group)
		{
			return groupSet.add(group);
		}

		// set returns false is group doesnt exist
		public synchronized boolean deleteGroup(String group)
		{
			return groupSet.remove(group);
		}

		// gets all users that belong to the given group
		public synchronized ArrayList<String> getGroupMembers(String group)
		{
			ArrayList<String> memList = new ArrayList<String>();
			for(String user: list.keySet())
			{
				if (list.get(user).getGroups().contains(group))
				{
					memList.add(user);
				}
			}
			return memList;
		}

		public synchronized void addUser(String username, String password)
		{
			// Check the username requirements
			if(isValidUsername(username)){
				if(isValidPassword(password)){
					byte[] pwd_hash;
					try{
						MessageDigest md = MessageDigest.getInstance("SHA-256");
						// add password hash and boolean for passwordNeedsChanged (true on creation, set to false on first login)
						md.update(password.getBytes());
						pwd_hash = md.digest();
					}
					catch(Exception e){
						System.out.println("Error generating password hash: " + e);
						return;
					}

					User newUser = new User();
					newUser.pwd_hash = pwd_hash;
					newUser.passwordNeedsChanged = true;
					newUser.locked = false;
					list.put(username, newUser);
					System.out.println("This is the user: " + list.get(username));
				}
				else{
					System.out.println("Invalid Password.");
					System.out.println("Passwords must be at least 8 characters long and contain one number, one upper case letter, one lower case letter.");
					System.out.println("Some special characters are not allowed");
					return;

				}
			}
			else{
				System.out.println("Invalid Username.");
				System.out.println("Usernames must be at least 4 characters long and contain only letters and numbers.");
				return;
			}

		}

		public synchronized void deleteUser(String username)
		{
			list.remove(username);
		}

		public synchronized boolean checkUser(String username)
		{
			if(list.containsKey(username))
			{
				return true;
			}
			else
			{
				return false;
			}
		}

		public synchronized boolean checkPassword(String username, String password){
      byte[] pwd_hash;
			try{
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				// add password hash and boolean for passwordNeedsChanged (true on creation, set to false on first login)
				md.update(password.getBytes());
				pwd_hash = md.digest();
			}
			catch(Exception e){
				System.out.println("Error generating password hash: " + e);
				return false;
			}
			User check_user = list.get(username);
			if(!Arrays.equals(check_user.pwd_hash, pwd_hash)){
				return false;
			}
			return true;
		}

		public synchronized boolean firstLogin(String username){

			User check_user = list.get(username);
			if(check_user.passwordNeedsChanged){
				return true;
			}
			return false;
		}

		public synchronized boolean resetPassword(String username, String password){
      byte[] pwd_hash;
			byte[] old_pwd;
			if(!isValidPassword(password)){
				return false;
			}
			try{
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				md.update(password.getBytes());
				pwd_hash = md.digest();
			}
			catch(Exception e){
				System.out.println("Error generating password hash: " + e);
				return false;
			}
			User check_user = list.get(username);
			old_pwd = check_user.pwd_hash;
			// Set the user's password to the new hash
			check_user.pwd_hash = pwd_hash;
			if(Arrays.equals(check_user.pwd_hash, old_pwd)){
				return false;
			}
			check_user.passwordNeedsChanged = false;
			return true;
		}

		public synchronized ArrayList<String> getUserGroups(String username)
		{
				return list.get(username).getGroups();
		}

		public synchronized ArrayList<String> getUserOwnership(String username)
		{
			return list.get(username).getOwnership();
		}

		public synchronized void addGroup(String user, String groupname)
		{
				list.get(user).addGroup(groupname);
		}

		public synchronized void removeGroup(String user, String groupname)
		{
				list.get(user).removeGroup(groupname);
		}

		public synchronized void addOwnership(String user, String groupname)
		{
				list.get(user).addOwnership(groupname);
		}

		public synchronized void removeOwnership(String user, String groupname)
		{
				list.get(user).removeOwnership(groupname);
		}

		public boolean isValidPassword(String password){
			boolean onelower = false;
			boolean oneupper = false;
			boolean onenum = false;
			if(password.length() < 8) return false;
			for(char ch: password.toCharArray()){
				if(Character.isUpperCase(ch)){
					oneupper = true;
				}
				else if(Character.isLowerCase(ch)){
					onelower = true;
				}
				else if(Character.isDigit(ch)){
					onenum = true;
				}
				// predetermined invalid characters
				else if(ch == ' ' || ch == '*' || ch == ';' || ch =='\\' || ch == '-'){
					return false;
				}
			}
			return (onelower && oneupper && onenum);
		}
		public boolean isValidUsername(String username){
			if(username.length() < 3) return false;
			for(char ch: username.toCharArray()){
				if(!Character.isLetterOrDigit(ch)){
					return false;
				}
			}
			return true;
		}


	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private byte[] pwd_hash;
		private boolean passwordNeedsChanged;
		private boolean locked;

		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public synchronized void changePassword(String pwd){
			byte[] hash;
			try{
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				// add password hash and boolean for passwordNeedsChanged (true on creation, set to false on first login)
				md.update(pwd.getBytes());
				hash = md.digest();
			}
			catch(Exception e){
				System.out.println("Error generating password hash: " + e);
				return;
			}
			pwd_hash = hash;
		}

		public synchronized ArrayList<String> getGroups()
		{
			return groups;
		}

		public synchronized boolean unlockUser()
		{
			locked = false;
			return !locked;
		}

		public synchronized boolean lockUser()
		{
			locked = true;
			return locked;
		}

		public synchronized ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public synchronized void addGroup(String group)
		{
			groups.add(group);
		}

		public synchronized void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public synchronized void addOwnership(String group)
		{
			ownership.add(group);
		}

		public synchronized void removeOwnership(String group)
		{
			if(!ownership.isEmpty())
			{
				if(ownership.contains(group))
				{
					ownership.remove(ownership.indexOf(group));
				}
			}
		}

	}
}
