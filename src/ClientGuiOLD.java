import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

class ClientGuiOLD {
  public static UserToken utkn = null;
  public static GroupClient gcli = new GroupClient();
  public static FileClient fcli = new FileClient();
  public static JTextArea ta = new JTextArea();
  public static String GIP = "127.0.0.1";
  public static String FIP = "127.0.0.1";
  public static String GPORT = "8765";
  public static String FPORT = "4321";
  public static String[] cmd = null;

  public static void main(String args[]) {

    JFrame frame = new JFrame("File Sharing System");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(1500, 600);

    JPanel panel1 = new JPanel();
    JLabel giplabel = new JLabel("Group Server IP: ");
    JTextField giptf = new JTextField(16);
    panel1.add(giplabel);
    panel1.add(giptf);
    JLabel gportlabel = new JLabel("Group Server Port: ");
    JTextField gporttf = new JTextField(4);
    panel1.add(gportlabel);
    panel1.add(gporttf);

    JLabel fiplabel = new JLabel("File Server IP: ");
    JTextField fiptf = new JTextField(16);
    panel1.add(fiplabel);
    panel1.add(fiptf);
    JLabel fportlabel = new JLabel("File Server Port: ");
    JTextField fporttf = new JTextField(4);
    panel1.add(fportlabel);
    panel1.add(fporttf);

    JButton connect = new JButton("Connect");
    JButton defaults = new JButton("Connect with Defaults");
    panel1.add(connect);
    panel1.add(defaults);

    JPanel panel2 = new JPanel();
    JLabel cmdlabel = new JLabel("Command: ");
    JTextField cmdtf = new JTextField(20);
    JButton entercmd = new JButton("Enter Command");
    panel2.add(cmdlabel);
    panel2.add(cmdlabel);
    panel2.add(cmdtf);
    panel2.add(entercmd);
    JButton exit = new JButton("Exit");
    panel2.add(exit);

    ta.append("Enter IPs/ports and click \"Connect\" to start.\n");
    ta.append("To use default values, click \"Connect with Defaults\"");

    frame.getContentPane().add(BorderLayout.SOUTH, panel2);
    frame.getContentPane().add(BorderLayout.NORTH, panel1);
    frame.getContentPane().add(BorderLayout.CENTER, ta);
    frame.setVisible(true);

    // log in with defaults
    defaults.addActionListener(new ActionListener(){
      public void actionPerformed(ActionEvent e){
        giptf.setText(GIP);
        gporttf.setText(GPORT);
        fiptf.setText(FIP);
        fporttf.setText(FPORT);
        ta.setText("Connection with defaults...");
        connect(GIP, FIP, Integer.parseInt(GPORT), Integer.parseInt(FPORT));
      }
    });

    // log in with specified values.
    connect.addActionListener(new ActionListener(){
      public void actionPerformed(ActionEvent e){
        GIP = giptf.getText();
        GPORT = gporttf.getText();
        FIP = fiptf.getText();
        FPORT = fporttf.getText();
        ta.setText("Connection with specified values...");
        connect(GIP, FIP, Integer.parseInt(GPORT), Integer.parseInt(FPORT));
      }
    });

    // log in with specified values.
    exit.addActionListener(new ActionListener(){
      public void actionPerformed(ActionEvent e){
        GIP = giptf.getText();
        GPORT = gporttf.getText();
        FIP = fiptf.getText();
        FPORT = fporttf.getText();
        ta.setText("Exiting...");
        ta.append("Bye!");
        exit();
      }
    });

    // enter something in the input box and click enter.
    entercmd.addActionListener(new ActionListener(){
      public void actionPerformed(ActionEvent e){
        cmd = cmdtf.getText().split(", ");
        switch(cmd[0]){
          case "1":
            login();
            cmdtf.setText("");
            break;
          case "2":
            createUser();
            cmdtf.setText("");
            break;
          case "3":
            deleteUser();
            cmdtf.setText("");
            break;
          case "4":
            createGroup();
            cmdtf.setText("");
            break;
          case "5":
            deleteGroup();
            cmdtf.setText("");
            break;
          case "6":
            addUserToGroup();
            cmdtf.setText("");
            break;
          case "7":
            deleteUserFromGroup();
            cmdtf.setText("");
            break;
          case "8":
            listGroupMembers();
            cmdtf.setText("");
            break;
          case "9":
            listFiles();
            cmdtf.setText("");
            break;
          case "10":
            upload();
            cmdtf.setText("");
            break;
          case "11":
            download();
            cmdtf.setText("");
            break;
          case "12":
            deleteFile();
            cmdtf.setText("");
            break;
          default:
            break;
        }
      }
    });
  }

  private static void connect(String gip, String fip, int gport, int fport){
    boolean gconn = gcli.connect(gip, gport);
    boolean fconn = fcli.connect(fip, fport);
    if(!(gconn)){
      ta.setText("Error connecting to group server.");
    }
    if(!(fconn)){
      ta.setText("Error connecting to file server.");
    }
    else ta.setText("Connected!\n");
    printMenu();
  }

  private static void printMenu(){
    ta.append("What would you like to do?\n");
    ta.append("Please select from the following operations: \n\n");
    ta.append("1. To Log in, enter \"1, <username>\"\n");
    ta.append("2. To Create a new user, enter \"2, <username>\"\n");
    ta.append("3. To Delete a user, enter \"3, <username>\"\n");
    ta.append("4. To Create a new group, enter \"4, <groupname>\"\n");
    ta.append("5. To Delete a group, enter \"5, <groupname>\"\n");
    ta.append("6. To Add a user to a group, enter \"6, <username>, <groupname>\"\n");
    ta.append("7. To Remove a user from a group, enter \"7, <username>, <groupname>\"\n");
    ta.append("8. To List all members of a group, enter \"8, <groupname>\"\n");
    ta.append("9. To List files, enter 9\n");
    ta.append("10. To Upload a file, enter \"10, <sourcefilename>, <destinationfilename>, <groupname>\"\n");
    ta.append("11. To Download a file, enter \"11, <sourcefilename>, <destinationfilename>\"\n");
    ta.append("12. To Delete a file, enter \"12, <filename>\"\n");
  }

  private static boolean checkLogInStatus(){
    if(utkn == null){
      ta.setText("\nNo user session found. Please log in with option 1.\n\n");
      printMenu();
      return false;
    }
    return true;
  }

  private static void login(){
    ta.setText("\nLog in\n");
    utkn = gcli.getToken(cmd[1]);
    ta.append("Logged in as " + utkn.getSubject() + "\n\n\n");
    printMenu();
  }

  private static void createUser(){
    ta.setText("\nCreate a new user\n\n");
    if(checkLogInStatus()){
      boolean create = gcli.createUser(cmd[1], utkn);
      if(!create) ta.append("An error occurred creating user " + cmd[1] + "\n");
      else ta.append("User " + cmd[1] + " created successfully!\n\n\n");
      printMenu();
    }
  }

  private static void deleteUser(){
    ta.setText("\nDelete a user\n\n");
    if(checkLogInStatus()){
      boolean delete = gcli.deleteUser(cmd[1], utkn);
      if(!delete) ta.append("An error occurred deleting user " + cmd[1] + "\n");
      else ta.append("User " + cmd[1] + " deleted successfully!\n\n\n");
      printMenu();
    }
  }

  private static void createGroup(){
    ta.setText("\nCreate a group\n");
    if(checkLogInStatus()){
      boolean Gcreate = gcli.createGroup(cmd[1], utkn);
      if(!Gcreate) ta.append("An error occurred creating group " + cmd[1] + "\n\n\n");
      else ta.append("Group " + cmd[1] + " created successfully!\n\n\n");
      printMenu();
    }
  }

  private static void deleteGroup(){
    ta.setText("\nCreate a group\n");
    if(checkLogInStatus()){
      boolean Gdelete = gcli.deleteGroup(cmd[1], utkn);
      if(!Gdelete) ta.append("An error occurred deleting group " + cmd[1] + "\n\n\n");
      else ta.append("Group " + cmd[1] + " deleted successfully!\n\n\n");
      printMenu();
    }
  }

  private static void addUserToGroup(){
    ta.setText("\nAdd a user to a group\n");
    if(checkLogInStatus()){
      boolean addToG = gcli.addUserToGroup(cmd[1], cmd[2], utkn);
      if(!addToG) ta.append("An error occurred adding user " + cmd[1] + " to group " + cmd[2] + "\n\n\n");
      else ta.append("User " + cmd[1] + " successfully added to " + cmd[2] + "!\n\n\n");
      printMenu();
    }
  }

  private static void deleteUserFromGroup(){
    ta.setText("\nDelete a user form a group\n");
    if(checkLogInStatus()){
      boolean delToG = gcli.deleteUserFromGroup(cmd[1], cmd[2], utkn);
      if(!delToG) ta.append("An error occurred deleting user " + cmd[1] + " from group " + cmd[2] + "\n\n\n");
      else ta.append("User " + cmd[1] + " successfully deleted from " + cmd[2] + "!\n");
      printMenu();
    }
  }

  private static void listGroupMembers(){
    ta.setText("\nList all members of a group\n");
    if(checkLogInStatus()){
      java.util.List<String> mems  = gcli.listMembers(cmd[1], utkn);
      if(mems == null) ta.append("An error occurred getting users from " + cmd[1] + ".\n\n\n");
      else {
        ta.append("Members in Group " + cmd[1] + ": \n");
        for(String mem: mems){
          ta.append(mem+"\n");
        }
        ta.append("\n\n\n");
      }
      printMenu();
    }
  }

  private static void listFiles(){
    ta.setText("\nList files\n");
    if(checkLogInStatus()){
      // FileThread should check the user's groups from the token
      java.util.List<String> files  = fcli.listFiles(utkn);
      ta.append("The files that user " + utkn.getSubject() + "can access are: \n\n\n");
      for(String f: files){
        ta.append(f+"\n");
      }
      ta.append("\n\n\n");
      printMenu();
    }
  }

  private static void upload(){
    ta.setText("\nUpload a file\n");
    if(checkLogInStatus()){
      if(!fcli.upload(cmd[1], cmd[2], cmd[3], utkn)) ta.append("Error uploading file to file server.\n\n\n");
      else ta.append("File successfully uploaded to file server!\n\n\n");
      printMenu();
    }
  }

  private static void download(){
    ta.setText("\nDownload a file\n");
    if(checkLogInStatus()){
      if(!fcli.download(cmd[1], cmd[2], utkn)) ta.append("Error downloading file.\n\n\n");
      else ta.append("File successfully downloaded!\n\n\n");
      printMenu();
    }
  }

  private static void deleteFile(){
    ta.setText("\nDelete a file\n");
    if(checkLogInStatus()){
      if(!fcli.delete(cmd[1], utkn)) ta.append("Error deleting file from file server.\n\n\n");
      else ta.append("File successfully deleted from file server!\n\n\n");
      printMenu();
    }
  }

  private static void exit(){
    gcli.disconnect();
    fcli.disconnect();
    System.exit(0);
  }

}
