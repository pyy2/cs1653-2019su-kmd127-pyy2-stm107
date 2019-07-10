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
    boolean gconn = gcli.connect(GIP, GPORT, "group", clientNum);
    boolean fconn = fcli.connect(FIP, FPORT, "file", clientNum);

    if (!(gconn)) {
      System.out.println("Error connecting to group server. Exiting...");
      System.exit(1);
    }

    if (!(fconn)) {
      System.out.println("Error connecting to file server. Exiting...");
      System.exit(1);
    }
    boolean loggedin = false;
    while (!loggedin){
      loggedin = login();
    }
      printMenu();
  }

  public static void printMenu() {
    while (true) {
      System.out.println("What would you like to do?");
      System.out.println("Please select from the following operations (please enter a number 1-15): ");
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
      System.out.println("14. Logout");
      System.out.println("15. Exit");
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
        logout();
        break;
      case "15":
        exit();
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
      System.out.println("Shutting down...\n\n\n");
      System.exit(0);
    }
    if (!gcli.userExists(username)) {
      // intentionally non-specific error message.
      System.out.println("Error logging in.\n\n");
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
      if (!gcli.resetPassword(username, new_password)) {
        System.out.println("Error changing password! New password cannot equal old password\n\n");
        // don't return, just let them continue.
      } else
        System.out.println("Password changed successfully!\n\n");
    }
    utkn = gcli.getToken(username);

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
    System.out.println("Logged out.\n\n");
    login();
  }

  // TODO: Implement account locking.
  // private static void unlockUser(){
  // System.out.println("\nLog in\n");
  // System.out.print("Please enter Administrator username: ");
  // String admin = kb.nextLine();
  // System.out.print("Please enter Administrator password: ");
  // String adminPass = kb.nextLine();
  // if (!gcli.userExists(admin)) {
  // // intentionally non-specific error message.
  // System.out.println("Could not verify Administrator account.\n\n");
  // return;
  // }
  // // Check for password match
  // if (!gcli.checkPassword(admin, adminPass)) {
  // // intentionally non-specific error message.
  // System.out.println("Could not verify Administrator account.\n\n");
  // return;
  // }
  // utkn = gcli.getToken(admin);
  // if(!utkn.getGroups().contains("ADMIN")){
  // System.out.println("Insufficient privileges to unlock user accounts!");
  // return;
  // }
  // // Get the user to unlock
  // System.out.print("Please enter username to unlock: ");
  // String user = kb.nextLine();
  // if(gcli.unlockUser(user)){
  // System.out.println("User unlocked!");
  // return;
  // }
  // System.out.println("Error unlocking user!");
  // }

  private static void resetPassword() {
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
  }

  private static void deleteGroup() {
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
  }

  private static void addUserToGroup() {
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
      utkn = gcli.getToken(utkn.getSubject());
    }
  }

  private static void deleteUserFromGroup() {
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
      utkn = gcli.getToken(utkn.getSubject());
    }
  }

  private static void listGroupMembers() {
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
    System.out.println("\nList files\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    // FileThread should check the user's groups from the token
    List<String> files = fcli.listFiles(utkn);
    System.out.println("The files that user " + utkn.getSubject() + " can access are: ");
    for (String f : files) {
      System.out.println(f);
    }
    System.out.println();
  }

  private static void upload() {
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
    utkn = gcli.getToken(utkn.getSubject());
    if (!fcli.upload(upSrc, upDest, upGroup, utkn))
      System.out.println("Error uploading file to file server.\n");
    else
      System.out.println("File successfully uploaded to file server!\n");
  }

  private static void download() {
    System.out.println("\nDownload a file\n");
    utkn = bounceToken();
    if (!checkLogInStatus())
      return;
    System.out.print("Please enter the name of the file you wish to download: ");
    String downSrc = kb.nextLine();
    System.out.print("Please enter the name for the destination: ");
    String downDest = kb.nextLine();
    utkn = gcli.getToken(utkn.getSubject());
    if (!fcli.download(downSrc, downDest, utkn))
      System.out.println("Error downloading file.\n");
    else
      System.out.println("File successfully downloaded!\n");
  }

  private static void deleteFile() {
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

  private static UserToken bounceToken() {
    // Bounce the server connections and re-login
    gcli.disconnect();
    gcli.connect(GIP, GPORT, "group", clientNum);
    fcli.disconnect();
    fcli.connect(FIP, FPORT, "file", clientNum);
    String uname = utkn.getSubject();
    return gcli.getToken(uname);
  }
}
