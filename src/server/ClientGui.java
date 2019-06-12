import javax.swing.*;
import java.awt.*;
class ClientGui {
    public static void main(String args[]) {

        //Creating the Frame
        JFrame frame = new JFrame("File Sharing System");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(760, 500);

        JPanel panel = new JPanel();
        // Get Group Server Info
        JLabel giplabel = new JLabel("Group Server IP:");
        JTextField giptf = new JTextField(20);
        JLabel gportlabel = new JLabel("Group Server Port:");
        JTextField gporttf = new JTextField(20);

        // Get File Server Info
        JLabel fiplabel = new JLabel("File Server IP:");
        JTextField fiptf = new JTextField(20);
        JLabel fportlabel = new JLabel("File Server Port:");
        JTextField fporttf = new JTextField(20);

        // Set up buttons
        JButton defaults = new JButton("Use Defaults");
        JButton connect = new JButton("Connect");
        JButton disconnect = new JButton("Disconnect");
        JButton reset = new JButton("Clear");

        // Add it all to panel
        panel.add(giplabel);
        panel.add(giptf);
        panel.add(gportlabel);
        panel.add(gporttf);
        panel.add(fiplabel);
        panel.add(fiptf);
        panel.add(fportlabel);
        panel.add(fporttf);

        panel.add(defaults);
        panel.add(connect);
        panel.add(disconnect);
        panel.add(reset);

        //Adding Components to the frame.
        frame.getContentPane().add(BorderLayout.CENTER, panel);
        frame.setVisible(true);
    }
}
