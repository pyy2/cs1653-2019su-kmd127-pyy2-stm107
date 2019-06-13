import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

class ClientGui {
  public static UserToken utkn = null;
  public static GroupClient gcli = new GroupClient();
  public static FileClient fcli = new FileClient();
  public static JTextArea ta = new JTextArea();
  public static final String GIP = "127.0.0.1";
  public static final String FIP = "127.0.0.1";
  public static final String GPORT = "8765";
  public static final String FPORT = "4321";

  public static void main(String args[]) {

    JFrame frame = new JFrame("File Sharing System");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(1500, 400);

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
    JTextField cmdtf = new JTextField(50);
    JButton enter = new JButton("Enter");
    JButton reset = new JButton("Exit");
    panel2.add(cmdlabel);
    panel2.add(cmdlabel);
    panel2.add(cmdtf);
    panel2.add(enter);
    panel2.add(reset);

    ta.append("Enter IPs/ports and click \"Connect\" to start.\n");
    ta.append("To use default values, click \"Connect with Defaults\"");

    frame.getContentPane().add(BorderLayout.SOUTH, panel2);
    frame.getContentPane().add(BorderLayout.NORTH, panel1);
    frame.getContentPane().add(BorderLayout.CENTER, ta);
    frame.setVisible(true);

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
    ta.append("Please select from the following operations (please enter a number 1-12 in the command text box): \n\n");
    ta.append("1. Log in (Get user token)\n");
    ta.append("2. Create a new user.\n");
    ta.append("3. Delete a user.\n");
    ta.append("4. Create a new group.\n");
    ta.append("5. Delete a group.\n");
    ta.append("6. Add a user to a group.\n");
    ta.append("7. Remove a user from a group.\n");
    ta.append("8. List all members of a group.\n");
    ta.append("9. List files.\n");
    ta.append("10. Upload a file.\n");
    ta.append("11. Download a file.\n");
    ta.append("12. Delete a file.\n");
  }


}
