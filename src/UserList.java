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
			list.put(username, newUser);
			System.out.println("This is the user: " + list.get(username));
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


	class User implements java.io.Serializable {

		/**
		 *
		 */
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> groups;
		private ArrayList<String> ownership;
		private byte[] pwd_hash;
		private boolean passwordNeedsChanged;

		public User()
		{
			groups = new ArrayList<String>();
			ownership = new ArrayList<String>();
		}

		public void changePassword(String pwd){
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

		public ArrayList<String> getGroups()
		{
			return groups;
		}

		public ArrayList<String> getOwnership()
		{
			return ownership;
		}

		public void addGroup(String group)
		{
			groups.add(group);
		}

		public void removeGroup(String group)
		{
			if(!groups.isEmpty())
			{
				if(groups.contains(group))
				{
					groups.remove(groups.indexOf(group));
				}
			}
		}

		public void addOwnership(String group)
		{
			ownership.add(group);
		}

		public void removeOwnership(String group)
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
