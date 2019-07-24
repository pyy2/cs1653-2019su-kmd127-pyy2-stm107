import java.util.*;

public class ClientDriver {
  public static Scanner kb;
  public static UserToken utkn = null;
  public static GroupClient gcli = new GroupClient();
  public static FileClient fcli = new FileClient();
  public static String GIP = "127.0.0.1";
  public static String FIP = "127.0.0.1";
  public static int GPORT = 8765;
  public static int FPORT = 4321;
  private static String clientNum;
  private static int loginFails = 0;

  public static void main(String args[]) {
    kb = new Scanner(System.in);
    clientNum = "";
    System.out.println("Welcome to the File Sharing System!");
    System.out.print("Use default ip:port for group and file servers? (y/n): ");
    boolean def = kb.nextLine().toLowerCase().equals("y");

    if (!def) {
      System.out.print("Please enter the ip for the group server: ");
      GIP = kb.nextLine();
      System.out.print("Please enter the port for the group server: ");
      GPORT = Integer.parseInt(kb.nextLine());
      System.out.print("Please enter the ip for the file server: ");
      FIP = kb.nextLine();
      System.out.print("Please enter the port for the file server: ");
      FPORT = Integer.parseInt(kb.nextLine());
    }

    // So 2 different clients don't use same keyfile
    System.out.println("Client #: ");
    clientNum = Integer.toString(kb.nextInt());
    clientNum = clientNum.replaceAll("[^a-zA-Z0-9]", "");
    String flush = kb.nextLine();

    System.out
        .println("Connecting to group client at " + GIP + ":" + GPORT + " and file client at " + FIP + ":" + FPORT);

    // connect to servers
    boolean gconn = gcli.connect(GIP, GPORT, "group", clientNum, false);
    boolean fconn = fcli.connect(FIP, FPORT, "file", clientNum, false);

    if (!(gconn)) {
      System.out.println("Error connecting to group server. Exiting...");
      System.exit(1);
    }

    if (!(fconn)) {
      System.out.println("Error connecting to file server. Exiting...");
      System.exit(1);
    }
    boolean loggedin = false;
    while (!loggedin) {
      loggedin = login();
    }
    printMenu();
  }

  public static void printMenu() {
    while (true) {
      System.out.println("What would you like to do?");
      System.out.println("Please select from the following operations (please enter a number 1-16): ");
      System.out.println("1. Log in (Get user token)");
      System.out.println("2. Reset password.");
      System.out.println("3. Create a new user.");
      System.out.println("4. Delete a user.");
      System.out.println("5. Create a new group.");
      System.out.println("6. Delete a group.");
      System.out.println("7. Add a user to a group.");
      System.out.println("8. Remove a user from a group.");
      System.out.println("9. List all members of a group.");
      System.out.println("10. List files.");
      System.out.println("11. Upload a file.");
      System.out.println("12. Download a file.");
      System.out.println("13. Delete a file.");
      System.out.println("14. Unlock User");
      System.out.println("15. Logout");
      System.out.println("16. Exit");
      System.out.print(">> ");

      String command = kb.nextLine();

      switch (command) {
      case "1":
        login();
        break;
      case "2":
        resetPassword();
        break;
      case "3":
        createUser();
        break;
      case "4":
        deleteUser();
        break;
      case "5":
        createGroup();
        break;
      case "6":
        deleteGroup();
        break;
      case "7":
        addUserToGroup();
        break;
      case "8":
        deleteUserFromGroup();
        break;
      case "9":
        listGroupMembers();
        break;
      case "10":
        listFiles();
        break;
      case "11":
        upload();
        break;
      case "12":
        download();
        break;
      case "13":
        deleteFile();
        break;
      case "14":
        unlockUser();
        break;
      case "15":
        logout();
        break;
      case "16":
        exit();
        // This is hidden. It's here for testing.
      case "17":
        getKeys(null);
        break;
      default:
        System.out.println("\nI'm sorry, I didn't understand your input. Let's try again.\n");
      }
    }
  }

  private static boolean checkLogInStatus() {
    if (utkn == null) {
      System.out.println("\nNo user session found. Please log in.\n");
      return login();
    }
    return true;
  }

  private static boolean login() {
    System.out.println("\nLog in\n");
    System.out.print("Please enter your username: ");
    String username = kb.nextLine();
    System.out.print("Please enter your password: ");
    String password = kb.nextLine();
    if (loginFails > 1) {
      System.out.println("You have exceeded the maximum falied login attempts!");
      System.out.println("If you have forgotten your password, please contact an administrator.");
      System.out.println("You're account will be locked\n\n\n");
      gcli.lockUser(username);
      System.exit(0);
    }
    if (!gcli.userExists(username, FIP, FPORT)) {
      // intentionally non-specific error message.
      System.out.println("Error logging in.\n\n");
      gcli.expseq = 0;
      return false;
    }
    // Check for password match
    System.out.println("Verifying password...");
    if (!gcli.checkPassword(username, password)) {
      // intentionally non-specific error message.
      System.out.println("Error logging in.\n\n");
      loginFails++;
      return false;
    }
    if (gcli.firstLogin(username)) {
      System.out.println("It's your first time logging in. Please change your password.");
      System.out.print("Please enter new password: ");
      String new_password = kb.nextLine();
      boolean reset = gcli.resetPassword(username, new_password);
      ;
      while (!reset) {
        System.out.println(
            "Error changing password! Make sure you follow password requirements and that your new password is not the same as your old password!!\n\n");
        System.out.print("Please enter new password: ");
        new_password = kb.nextLine();
        reset = gcli.resetPassword(username, new_password);

      }
      System.out.println("Password changed successfully!\n\n");
    }
    utkn = gcli.getToken(username, FIP, FPORT);

    if (utkn != null) {
      System.out.println("Logged in as " + utkn.getSubject() + "\n");
      return true;
    } else {
      System.out.println("Error when logging in with the requested user.\n");
      return false;
    }
  }

  private static void logout() {
    utkn = null;
    bounceToken();
    // reset the seq number
    gcli.expseq = 0;
    System.out.println("Logged out.\n\n");
    login();
  }

  private static void unlockUser() {
    checkExpiration();
    System.out.println("\nLog in\n");
    System.out.print("Please enter Administrator username: ");
    String admin = kb.nextLine();
    System.out.print("Please enter Administrator password: ");
    String adminPass = kb.nextLine();
    if (!gcli.userExists(admin, FIP, FPORT)) {
      // intentionally non-specific error message.
      System.out.println("Could not verify Administrator account.\n\n");
      return;
    }
    // Check for password match
    if (!gcli.checkPassword(admin, adminPass)) {
      // intentionally non-specific error message.
      System.out.println("Could not verify Administrator account.\n\n");
      return;
    }
    utkn = gcli.getToken(admin, FIP, FPORT);
    if (!utkn.getGroups().contains("ADMIN")) {
      System.out.println("Insufficient privileges to unlock user accounts!");
      return;
    }
    // Get the user to unlock
    System.out.print("Please enter username to unlock: ");
    String user = kb.nextLine();
    if (gcli.unlockUser(user)) {
      System.out.println("User unlocked!");
      return;
    }
    System.out.println("Error unlocking user!");
  }

  private static void resetPassword() {
    checkExpiration();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter your username: ");
    String username = kb.nextLine();
    System.out.print("Please enter your old password: ");
    String old_pass = kb.nextLine();
    // verify old password is known!
    if (!gcli.checkPassword(username, old_pass)) {
      System.out.println("Current password incorrect.\n\n");
      return;
    }
    System.out.print("Please enter new password: ");
    String new_password = kb.nextLine();
    while (!gcli.resetPassword(username, new_password)) {
      System.out.println(
          "Error changing password! Make sure you follow password requirements and that your new password is not the same as your old password!!\n\n");
      return;
    }
    System.out.println("Password changed successfully!\n\n");
  }

  private static void createUser() {
    checkExpiration();
    System.out.println("\nCreate a new user\n");
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the new user's username: ");
    String newName = kb.nextLine();
    System.out.print("Please enter a temporary password for the user: ");
    String pwd = kb.nextLine();
    boolean create = gcli.createUser(newName, pwd, utkn);
    if (!create)
      System.out.println("An error occurred creating user " + newName + "\n");
    else {
      System.out.println("User " + newName + " created successfully!");
      System.out.println(
          "NOTE: The temporary password will need to be changed when the user logs in for the first time.\n\n");
    }

  }

  private static void deleteUser() {
    checkExpiration();
    System.out.println("\nDelete a user\n");
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the username to delete: ");
    String delName = kb.nextLine();
    boolean delete = gcli.deleteUser(delName, utkn);
    if (!delete)
      System.out.println("An error occurred deleting user " + delName + "\n");
    else
      System.out.println("User " + delName + " deleted successfully!\n");
  }

  private static void createGroup() {
    checkExpiration();
    utkn = bounceToken();
    System.out.println("\nCreate a group\n");
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the new group's name: ");
    String newGName = kb.nextLine();
    boolean Gcreate = gcli.createGroup(newGName, utkn);
    if (!Gcreate)
      System.out.println("An error occurred creating group " + newGName + "\n");
    else
      System.out.println("Group " + newGName + " created successfully!\n");
    utkn = bounceToken();
  }

  private static void deleteGroup() {
    checkExpiration();
    System.out.println("\nDelete a group\n");
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the group to delete: ");
    String delGName = kb.nextLine();
    boolean Gdelete = gcli.deleteGroup(delGName, utkn);
    if (!Gdelete)
      System.out.println("An error occurred deleting group " + delGName + "\n");
    else
      System.out.println("Group " + delGName + " deleted successfully!\n");
    utkn = bounceToken();
  }

  private static void addUserToGroup() {
    checkExpiration();
    System.out.println("\nAdd a user to a group\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the user to add: ");
    String addgName = kb.nextLine();
    System.out.print("Please enter the group to add " + addgName + " to: ");
    String addToGName = kb.nextLine();
    boolean addToG = gcli.addUserToGroup(addgName, addToGName, utkn);
    if (!addToG)
      System.out.println("An error occurred adding user " + addgName + " to group " + addToGName + "\n");
    else {
      System.out.println("User " + addgName + " successfully added to " + addToGName + "!\n");
      // refresh the token to add the groups.
      // This covers the scenario where you add yourself to a group.
      utkn = gcli.getToken(utkn.getSubject(), FIP, FPORT);
    }
  }

  private static void deleteUserFromGroup() {
    checkExpiration();
    System.out.println("\nDelete a user form a group\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the user to delete: ");
    String delgName = kb.nextLine();
    System.out.print("Please enter the group to delete from " + delgName + ": ");
    String delToGName = kb.nextLine();
    boolean delToG = gcli.deleteUserFromGroup(delgName, delToGName, utkn);
    if (!delToG)
      System.out.println("An error occurred deleting user " + delgName + " from group " + delToGName + "\n");
    else {
      System.out.println("User " + delgName + " successfully deleted from " + delToGName + "!\n");
      // refresh the token to add the groups.
      // This covers the scenario where you add yourself to a group.
      utkn = gcli.getToken(utkn.getSubject(), FIP, FPORT);
    }
  }

  private static void listGroupMembers() {
    checkExpiration();
    System.out.println("\nList all members of a group\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the group name: ");
    String GCheck = kb.nextLine();
    List<String> mems = gcli.listMembers(GCheck, utkn);
    if (mems == null)
      System.out.println("An error occurred getting users from " + GCheck + ".\n");
    else {
      System.out.println("Members in Group " + GCheck + ": ");
      for (String mem : mems) {
        System.out.println(mem);
      }
      System.out.println();
    }
  }

  private static void listFiles() {
    checkExpiration();
    System.out.println("\nList files\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    // FileThread should check the user's groups from the token
  //  System.out.println(utkn.toString());
    List<String> files = fcli.listFiles(utkn);
    System.out.println("The files that user " + utkn.getSubject() + " can access are: ");
    for (String f : files) {
      System.out.println(f);
    }
    System.out.println();
  }

  private static void upload() {
    checkExpiration();
    System.out.println("\nUpload a file\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the path for the file you wish to upload: ");
    String upSrc = kb.nextLine();
    System.out.print("Please enter the name for the destination: ");
    String upDest = kb.nextLine();
    System.out.print("Please enter the group to which you want to upload the file: ");
    String upGroup = kb.nextLine();
    utkn = gcli.getToken(utkn.getSubject(), FIP, FPORT);

    // Get the current group keys
    Hashtable<Integer, byte[]> key_info = getKeys(upGroup);
    if (!key_info.keys().hasMoreElements()) {
      System.out.println("Error uploading file to file server.\n");
      return;
    }
    int n = key_info.keys().nextElement();
    byte[] key = key_info.get(n);
    // System.out.println("The key the clidriver is sending to upload is: " + new
    // String(key));
    if (!fcli.upload(upSrc, upDest, upGroup, utkn, n, key))
      System.out.println("Error uploading file to file server.\n");
    else
      System.out.println("File successfully uploaded to file server!\n");
  }

  private static void download() {
    checkExpiration();
    System.out.println("\nDownload a file\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the name of the file you wish to download: ");
    String downSrc = kb.nextLine();
    System.out.print("Please enter the name for the destination: ");
    String downDest = kb.nextLine();
    System.out.print("Please enter the group in which the file resides: ");
    String group = kb.nextLine();
    utkn = gcli.getToken(utkn.getSubject(), FIP, FPORT);

    // Get the current group keys for download decryption
    Hashtable<Integer, byte[]> key_info = getKeys(group);
    if (!key_info.keys().hasMoreElements()) {
      System.out.println("Error downloading file.\n");
      return;
    }
    int n = key_info.keys().nextElement();
    byte[] key = key_info.get(n);
    // System.out.println("The key the clidriver is sending to download is: " + new
    // String(key));

    if (!fcli.download(downSrc, downDest, utkn, n, key))
      System.out.println("Error downloading file.\n");
    else
      System.out.println("File successfully downloaded!\n");
  }

  private static void deleteFile() {
    checkExpiration();
    System.out.println("\nDelete a file\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the name of the file you wish to delete: ");
    String delSrc = kb.nextLine();
    if (!fcli.delete(delSrc, utkn))
      System.out.println("Error deleting file from file server.\n");
    else
      System.out.println("File successfully deleted from file server!\n");
  }

  private static void exit() {
    System.out.println("\nDisconnecting from servers...\n");
    gcli.disconnect();
    fcli.disconnect();
    System.out.println("Bye!");
    System.exit(0);
  }

  private static Hashtable<Integer, byte[]> getKeys(String group) {
    checkExpiration();
    if (group == null) {
      System.out.println("No group name found.");
      System.out.print("Please enter the name of the groups for which you need keys: ");
      group = kb.nextLine();
    }
    Hashtable<Integer, byte[]> n_key = new Hashtable<>();
    System.out.println("\nGetting group keys\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return null;
    String keys = gcli.getKeys(group, utkn);
    if (keys == null)
      System.out.println("Error getting group keys. You may not have permission, or the group/key doesn't exist.\n");
    else {
      System.out.println("Looks like you're allowed. Here's yo' key!\n");
      int indexofDelim = keys.indexOf("~");
      int n = Integer.parseInt(keys.substring(0, indexofDelim));
      String keystr = keys.substring(indexofDelim + 1);
      try {
        n_key.put(n, keystr.getBytes("ISO-8859-1"));
      } catch (Exception e) {
        System.out.println("Error getting key bytes: " + e);
      }

    }
    return n_key;
  }

  private static UserToken bounceToken() {
    // Bounce the server connections and re-login
    gcli.expseq = 0;
    fcli.expseq = 0;
    gcli.disconnect();
    // make bouncing token invisible
    gcli.connect(GIP, GPORT, "group", clientNum, true);
    // gcli.expseq = gexp;
    fcli.disconnect();
    fcli.connect(FIP, FPORT, "file", clientNum, true);
    // fcli.expseq = fexp;
    if (utkn == null) {
      return null;
    }
    String uname = utkn.getSubject();
    // System.out.println("This is the exp: "+gexp);
    return gcli.getToken(uname, FIP, FPORT);
  }

  private static void checkExpiration() {
    long currTime = System.currentTimeMillis();
    boolean expired = currTime > utkn.getEXPtime();
    if (expired) {
      System.out.println("YOUR USER SESSION HAS EXPIRED!!!");
      System.out.println("Please log in again.");
      login();
    }
  }
}
