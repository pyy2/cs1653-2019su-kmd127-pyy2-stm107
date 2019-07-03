import java.util.*;

public class ClientDriver{
  public static Scanner kb;
  public static UserToken utkn = null;
  public static GroupClient gcli = new GroupClient();
  public static FileClient fcli = new FileClient();
  public static String GIP = "127.0.0.1";
  public static String FIP = "127.0.0.1";
  public static int GPORT = 8765;
  public static int FPORT = 4321;

  public static void main(String args[]){
    kb = new Scanner(System.in);
    System.out.println("Welcome to the File Sharing System!");
    System.out.print("Use default ip:port for group and file servers? (y/n): ");
    boolean def = kb.nextLine().toLowerCase().equals("y");

    if(!def){
      System.out.print("Please enter the ip for the group server: ");
      GIP = kb.nextLine();
      System.out.print("Please enter the port for the group server: ");
      GPORT = Integer.parseInt(kb.nextLine());
      System.out.print("Please enter the ip for the file server: ");
      FIP = kb.nextLine();
      System.out.print("Please enter the port for the file server: ");
      FPORT = Integer.parseInt(kb.nextLine());
    }

    System.out.println("Connecting to group client at " + GIP + ":" + GPORT + " and file client at " + FIP + ":" + FPORT);

    // connect to servers
    boolean gconn = gcli.connect(GIP, GPORT);
    boolean fconn = fcli.connect(FIP, FPORT);

    if(!(gconn)){
      System.out.println("Error connecting to group server. Exiting...");
      System.exit(1);
    }

    if(!(fconn)){
      System.out.println("Error connecting to file server. Exiting...");
      System.exit(1);
    }

    while(true){
      System.out.println("What would you like to do?");
      System.out.println("Please select from the following operations (please enter a number 1-13): ");
      System.out.println("1. Log in (Get user token)");
      System.out.println("2. Create a new user.");
      System.out.println("3. Delete a user.");
      System.out.println("4. Create a new group.");
      System.out.println("5. Delete a group.");
      System.out.println("6. Add a user to a group.");
      System.out.println("7. Remove a user from a group.");
      System.out.println("8. List all members of a group.");
      System.out.println("9. List files.");
      System.out.println("10. Upload a file.");
      System.out.println("11. Download a file.");
      System.out.println("12. Delete a file.");
      System.out.println("13. Exit");
      System.out.print(">> ");

      String command = kb.nextLine();

      switch(command){
        case "1":
          login();
          break;
        case "2":
          createUser();
          break;
        case "3":
          deleteUser();
          break;
        case "4":
          createGroup();
          break;
        case "5":
          deleteGroup();
          break;
        case "6":
          addUserToGroup();
          break;
        case "7":
          deleteUserFromGroup();
          break;
        case "8":
          listGroupMembers();
          break;
        case "9":
          listFiles();
          break;
        case "10":
          upload();
          break;
        case "11":
          download();
          break;
        case "12":
          deleteFile();
          break;
        case "13":
          exit();
        default:
          System.out.println("\nI'm sorry, I didn't understand your input. Let's try again.\n");
      }
    }
  }

  private static boolean checkLogInStatus(){
    if(utkn == null){
      System.out.println("\nNo user session found. Please log in.\n");
      return login();
    }
    return true;
  }

  private static boolean login(){
    System.out.println("\nLog in\n");
    System.out.print("Please enter your username: ");
    String username = kb.nextLine();
    System.out.print("Please enter your password: ");
    String password = kb.nextLine();
    if(!gcli.userExists(username)){
      //intentionally non-specific error message.
      System.out.println("Error logging in.\n\n");
      return false;
    }
    // Check for password match
    System.out.println("Verifying password...");
    if(!gcli.checkPassword(username, password)){
      //intentionally non-specific error message.
      System.out.println("Error logging in.\n\n");
      return false;
    }
    // if(gcli.my_gs.list.get(username).passwordNeedsChanged){
    //   System.out.println("It's your first time logging in. Please change your password.");
    //   System.out.print("Enter new password: ");
    //   String new_pwd = kb.nextLine();
    //   gcli.my_gs.list.get(username).changePassword(new_pwd);
    //   gcli.my_gs.list.get(username).passwordNeedsChanged = false;
    // }
    utkn = gcli.getToken(username);

    if(utkn != null){
      System.out.println("Logged in as " + utkn.getSubject() + "\n");
      return true;
    }
    else{
      System.out.println("Error when logging in with the requested user.\n");
      return false;
    }
  }

  private static void createUser(){
    System.out.println("\nCreate a new user\n");
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the new user's username: ");
    String newName = kb.nextLine();
    System.out.print("Please enter a temporary password for the user: ");
    String pwd = kb.nextLine();
    boolean create = gcli.createUser(newName, pwd, utkn);
    if(!create) System.out.println("An error occurred creating user " + newName + "\n");
    else{
      System.out.println("User " + newName + " created successfully!");
      System.out.println("NOTE: The temporary password will need to be changed when the user logs in for the first time.\n\n");
    }

  }

  private static void deleteUser(){
    System.out.println("\nDelete a user\n");
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the username to delete: ");
    String delName = kb.nextLine();
    boolean delete = gcli.deleteUser(delName, utkn);
    if(!delete) System.out.println("An error occurred deleting user " + delName + "\n");
    else System.out.println("User " + delName + " deleted successfully!\n");
  }

  private static void createGroup(){
    System.out.println("\nCreate a group\n");
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the new group's name: ");
    String newGName = kb.nextLine();
    boolean Gcreate = gcli.createGroup(newGName, utkn);
    if(!Gcreate) System.out.println("An error occurred creating group " + newGName + "\n");
    else System.out.println("Group " + newGName + " created successfully!\n");
  }

  private static void deleteGroup(){
    System.out.println("\nDelete a group\n");
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the group to delete: ");
    String delGName = kb.nextLine();
    boolean Gdelete = gcli.deleteGroup(delGName, utkn);
    if(!Gdelete) System.out.println("An error occurred deleting group " + delGName + "\n");
    else System.out.println("Group " + delGName + " deleted successfully!\n");
  }

  private static void addUserToGroup(){
    System.out.println("\nAdd a user to a group\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the user to add: ");
    String addgName = kb.nextLine();
    System.out.print("Please enter the group to add " + addgName + " to: ");
    String addToGName = kb.nextLine();
    boolean addToG = gcli.addUserToGroup(addgName, addToGName, utkn);
    if(!addToG) System.out.println("An error occurred adding user " + addgName + " to group " + addToGName + "\n");
    else{
      System.out.println("User " + addgName + " successfully added to " + addToGName + "!\n");
      // refresh the token to add the groups.
      // This covers the scenario where you add yourself to a group.
      utkn = gcli.getToken(utkn.getSubject());
    }
  }

  private static void deleteUserFromGroup(){
    System.out.println("\nDelete a user form a group\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the user to delete: ");
    String delgName = kb.nextLine();
    System.out.print("Please enter the group to delete from " + delgName + ": ");
    String delToGName = kb.nextLine();
    boolean delToG = gcli.deleteUserFromGroup(delgName, delToGName, utkn);
    if(!delToG) System.out.println("An error occurred deleting user " + delgName + " from group " + delToGName + "\n");
    else{
      System.out.println("User " + delgName + " successfully deleted from " + delToGName + "!\n");
      // refresh the token to add the groups.
      // This covers the scenario where you add yourself to a group.
      utkn = gcli.getToken(utkn.getSubject());
    }
  }

  private static void listGroupMembers(){
    System.out.println("\nList all members of a group\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the group name: ");
    String GCheck = kb.nextLine();
    List<String> mems  = gcli.listMembers(GCheck, utkn);
    if(mems == null) System.out.println("An error occurred getting users from " + GCheck + ".\n");
    else {
      System.out.println("Members in Group " + GCheck + ": ");
      for(String mem: mems){
        System.out.println(mem);
      }
      System.out.println();
    }
  }

  private static void listFiles(){
    System.out.println("\nList files\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    // FileThread should check the user's groups from the token
    List<String> files  = fcli.listFiles(utkn);
    System.out.println("The files that user " + utkn.getSubject() + " can access are: ");
    for(String f: files){
      System.out.println(f);
    }
    System.out.println();
  }

  private static void upload(){
    System.out.println("\nUpload a file\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the path for the file you wish to upload: ");
    String upSrc = kb.nextLine();
    System.out.print("Please enter the name for the destination: ");
    String upDest = kb.nextLine();
    System.out.print("Please enter the group to which you want to upload the file: ");
    String upGroup = kb.nextLine();
    utkn = gcli.getToken(utkn.getSubject());
    if(!fcli.upload(upSrc, upDest, upGroup, utkn)) System.out.println("Error uploading file to file server.\n");
    else System.out.println("File successfully uploaded to file server!\n");
  }

  private static void download(){
    System.out.println("\nDownload a file\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the name of the file you wish to download: ");
    String downSrc = kb.nextLine();
    System.out.print("Please enter the name for the destination: ");
    String downDest = kb.nextLine();
    utkn = gcli.getToken(utkn.getSubject());
    if(!fcli.download(downSrc, downDest, utkn)) System.out.println("Error downloading file.\n");
    else System.out.println("File successfully downloaded!\n");
  }

  private static void deleteFile(){
    System.out.println("\nDelete a file\n");
    utkn = bounceToken();
    if(!checkLogInStatus()) return;
    System.out.print("Please enter the name of the file you wish to delete: ");
    String delSrc = kb.nextLine();
    if(!fcli.delete(delSrc, utkn)) System.out.println("Error deleting file from file server.\n");
    else System.out.println("File successfully deleted from file server!\n");
  }

  private static void exit(){
    System.out.println("\nDisconnecting from servers...\n");
    gcli.disconnect();
    fcli.disconnect();
    System.out.println("Bye!");
    System.exit(0);
  }

  private static UserToken bounceToken(){
    // Bounce the server connections and re-login
    gcli.disconnect();
    gcli.connect(GIP, GPORT);
    fcli.disconnect();
    fcli.connect(FIP, FPORT);
    String uname = utkn.getSubject();
    return gcli.getToken(uname);
  }
}
