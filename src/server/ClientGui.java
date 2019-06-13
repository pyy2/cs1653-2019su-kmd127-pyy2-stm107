import javax.swing.*;
import java.awt.*;
class ClientGui {
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

        JTextArea ta = new JTextArea();
        ta.append("Enter IPs/ports and click \"Connect\" to start.\n");
        ta.append("To use default values, click \"Connect with Defaults\"");

        frame.getContentPane().add(BorderLayout.SOUTH, panel2);
        frame.getContentPane().add(BorderLayout.NORTH, panel1);
        frame.getContentPane().add(BorderLayout.CENTER, ta);
        frame.setVisible(true);
    }
}
