import java.util.*;

public class ClientDriver{
  public static Scanner kb;
  public static void main(String args[]){
    kb = new Scanner(System.in);
    String g_ip;
    String f_ip;
    int g_port;
    int f_port;
    System.out.println("Welcome to the File Sharing System!");
    System.out.print("Use default ip:port for group and file servers? (y/n): ");
    boolean def = kb.nextLine().toLowerCase().equals("y");
    if(def){
      g_ip = "127.0.0.1";
      f_ip = "127.0.0.1";
      g_port = 8765;
      f_port = 4321;
    }
    else{
      System.out.print("Please enter the ip for the group server: ");
      g_ip = kb.nextLine();
      System.out.print("Please enter the port for the group server: ");
      g_port = Integer.parseInt(kb.nextLine());
      System.out.print("Please enter the ip for the file server: ");
      f_ip = kb.nextLine();
      System.out.print("Please enter the port for the file server: ");
      f_port = Integer.parseInt(kb.nextLine());
    }
    System.out.println("Connecting to group client at " + g_ip + ":" + g_port + " and file client at " + f_ip + ":" + f_port);

    // Create and connect
    GroupClient gcli = new GroupClient();
    FileClient fcli = new FileClient();

    gcli.connect(g_ip, g_port);
    fcli.connect(f_ip, f_port);


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
          System.out.println("\nLog in\n");
          System.out.print("Please enter your username: ");
          UserToken utkn = gcli.getToken(kb.nextLine());
          System.out.println("Logged in as " + utkn.getSubject() + "\n");
          break;
        case "2":
          System.out.println("\nCreate a new user\n");
          break;
        case "3":
          System.out.println("\nDelete a user\n");
          break;
        case "4":
          System.out.println("\nCreate a group\n");
          break;
        case "5":
          System.out.println("\nDelete a group\n");
          break;
        case "6":
          System.out.println("\nAdd a user to a group\n");
          break;
        case "7":
          System.out.println("\nDelete a user form a group\n");
          break;
        case "8":
          System.out.println("\nList all members of a group\n");
          break;
        case "9":
          System.out.println("\nList files\n");
          break;
        case "10":
          System.out.println("\nUpload a file\n");
          break;
        case "11":
          System.out.println("\nDownload a file\n");
          break;
        case "12":
          System.out.println("\nDelete a file\n");
          break;
        case "13":
          System.out.println("\nDisconnecting from servers...\n");
          gcli.disconnect();
          fcli.disconnect();
          System.out.println("Bye!");
          System.exit(0);
        default:
          System.out.println("\nI'm sorry, I didn't understand your input. Let's try again.\n");
      }
    }
  }
}
