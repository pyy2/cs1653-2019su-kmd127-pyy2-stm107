// import javax.swing.*;
// import java.awt.*;
// import java.awt.event.*;

// class ClientGui {
// public static UserToken utkn = null;
// public static GroupClient gcli = new GroupClient();
// public static FileClient fcli = new FileClient();
// public static JTextArea ta = new JTextArea(100, 100);
// public static String GIP = "127.0.0.1";
// public static String FIP = "127.0.0.1";
// public static String GPORT = "8765";
// public static String FPORT = "4321";
// public static boolean loggedin = false;
// public static boolean connected = false;

// public static void main(String args[]) {

// JFrame frame = new JFrame("File Sharing System");
// frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
// frame.setSize(1500, 600);

// BoxLayout boxLayout = new BoxLayout(frame.getContentPane(),
// BoxLayout.Y_AXIS);
// frame.setLayout(boxLayout);

// //////////////// Connect Panel ///////////////
// JPanel conn_panel = new JPanel();
// JLabel giplabel = new JLabel("Group Server IP: ");
// JTextField giptf = new JTextField(16);
// conn_panel.add(giplabel);
// conn_panel.add(giptf);
// JLabel gportlabel = new JLabel("Group Server Port: ");
// JTextField gporttf = new JTextField(4);
// conn_panel.add(gportlabel);
// conn_panel.add(gporttf);

// JLabel fiplabel = new JLabel("File Server IP: ");
// JTextField fiptf = new JTextField(16);
// conn_panel.add(fiplabel);
// conn_panel.add(fiptf);
// JLabel fportlabel = new JLabel("File Server Port: ");
// JTextField fporttf = new JTextField(4);
// conn_panel.add(fportlabel);
// conn_panel.add(fporttf);

// JButton connect = new JButton("Connect");
// JButton defaults = new JButton("Connect with Defaults");
// conn_panel.add(connect);
// conn_panel.add(defaults);

// //////////////// Login Panel ///////////////
// JPanel login_panel = new JPanel();
// JLabel ulog = new JLabel("Username: ");
// JTextField ulogtf = new JTextField(10);
// login_panel.add(ulog);
// login_panel.add(ulogtf);

// JLabel passlog = new JLabel("Password: ");
// JTextField passlogtf = new JTextField(10);
// login_panel.add(passlog);
// login_panel.add(passlogtf);

// JButton loginbutton = new JButton("Login");
// JButton logout = new JButton("Logout");
// login_panel.add(loginbutton);
// login_panel.add(logout);

// JButton exit = new JButton("Exit");

// //////////////// Reset Password Panel ///////////////
// JPanel reset_panel = new JPanel();
// JLabel uRes = new JLabel("Username: ");
// JTextField uRestf = new JTextField(10);
// reset_panel.add(uRes);
// reset_panel.add(uRestf);

// JLabel rpasslog = new JLabel("Password: ");
// JTextField rpasslogtf = new JTextField(10);
// reset_panel.add(rpasslog);
// reset_panel.add(rpasslogtf);

// JLabel npasslog = new JLabel("New Password: ");
// JTextField npasslogtf = new JTextField(10);
// reset_panel.add(npasslog);
// reset_panel.add(npasslogtf);

// JButton resetbutton = new JButton("Reset Password");
// reset_panel.add(resetbutton);

// //////////////// Create User Panel ///////////////
// JPanel cu_panel = new JPanel();
// JLabel cuname = new JLabel("CREATE USER\nUsername: ");
// JTextField cutf = new JTextField(10);
// cu_panel.add(cuname);
// cu_panel.add(cutf);

// JLabel cupass = new JLabel("Password: ");
// JTextField passcutf = new JTextField(10);
// cu_panel.add(cupass);
// cu_panel.add(passcutf);

// JButton cubutton = new JButton("Click to Create User");
// cu_panel.add(cubutton);

// //////////////// Delete User Panel ///////////////
// JPanel du_panel = new JPanel();
// JLabel duname = new JLabel("DELETE USER\nUsername: ");
// JTextField dutf = new JTextField(10);
// du_panel.add(duname);
// du_panel.add(dutf);

// JButton dubutton = new JButton("Click to Delete User");
// du_panel.add(dubutton);

// //////////////// Create Group Panel ///////////////
// JPanel cg_panel = new JPanel();
// JLabel cgname = new JLabel("CREATE GROUP\nGroup Name: ");
// JTextField cgtf = new JTextField(10);
// cg_panel.add(cgname);
// cg_panel.add(cgtf);

// JButton cgbutton = new JButton("Click to Create Group");
// cg_panel.add(cgbutton);

// //////////////// Delete Group Panel ///////////////
// JPanel dg_panel = new JPanel();
// JLabel dgname = new JLabel("DELETE GROUP\nGroup Name: ");
// JTextField dgtf = new JTextField(10);
// dg_panel.add(dgname);
// dg_panel.add(dgtf);

// JButton dgbutton = new JButton("Click to Delete Group");
// dg_panel.add(dgbutton);

// //////////////// Add Group Member Panel ///////////////
// JPanel agu_panel = new JPanel();
// JLabel aguname = new JLabel("ADD GROUP MEMBER\nGroup Name: ");
// JTextField agutf = new JTextField(10);
// agu_panel.add(aguname);
// agu_panel.add(agutf);
// JLabel aguser = new JLabel("ADD GROUP MEMBER\nUsername: ");
// JTextField autf = new JTextField(10);
// agu_panel.add(aguser);
// agu_panel.add(autf);

// JButton agubutton = new JButton("Click to Add Group Member");
// agu_panel.add(agubutton);

// //////////////// Remove Group Member Panel ///////////////
// JPanel rgu_panel = new JPanel();
// JLabel rguname = new JLabel("REMOVE GROUP MEMBER\nGroup Name: ");
// JTextField rgutf = new JTextField(10);
// rgu_panel.add(rguname);
// rgu_panel.add(rgutf);
// JLabel rguser = new JLabel("REMOVE GROUP MEMBER\nUsername: ");
// JTextField rutf = new JTextField(10);
// rgu_panel.add(rguser);
// rgu_panel.add(rutf);

// JButton rgubutton = new JButton("Click to Remove Group Member");
// rgu_panel.add(rgubutton);

// //////////////// List Group Members Panel ///////////////
// JPanel lm_panel = new JPanel();
// JLabel lmname = new JLabel("LIST GROUP MEMBERS\nGroup Name: ");
// JTextField lmtf = new JTextField(10);
// lm_panel.add(lmname);
// lm_panel.add(lmtf);

// JButton lmbutton = new JButton("Click to List Group Members");
// lm_panel.add(lmbutton);

// //////////////// List Files Panel ///////////////
// JPanel lf_panel = new JPanel();
// JButton lfbutton = new JButton("Click to List All Files");
// lf_panel.add(lfbutton);

// //////////////// Upload File Panel ///////////////
// JPanel uf_panel = new JPanel();
// JLabel ufname = new JLabel("UPLOAD FILE\nSource Name: ");
// JTextField ufutf = new JTextField(10);
// uf_panel.add(ufname);
// uf_panel.add(ufutf);
// JLabel ufd = new JLabel("UPLOAD FILE\nDestination Name: ");
// JTextField ufdtf = new JTextField(10);
// uf_panel.add(ufd);
// uf_panel.add(ufdtf);
// JLabel ufg = new JLabel("UPLOAD FILE\nGroup Name: ");
// JTextField ufgtf = new JTextField(10);
// uf_panel.add(ufg);
// uf_panel.add(ufgtf);

// JButton ufbutton = new JButton("Click to Upload File");
// uf_panel.add(ufbutton);

// //////////////// Download File Panel ///////////////
// JPanel df_panel = new JPanel();
// JLabel dfname = new JLabel("DOWNLOAD FILE\nSource Name: ");
// JTextField dfutf = new JTextField(10);
// df_panel.add(dfname);
// df_panel.add(dfutf);
// JLabel dfd = new JLabel("DOWNLOAD FILE\nDestination Name: ");
// JTextField dfdtf = new JTextField(10);
// df_panel.add(dfd);
// df_panel.add(dfdtf);

// JButton dfbutton = new JButton("Click to Download File");
// df_panel.add(dfbutton);

// //////////////// Delete File Panel ///////////////
// JPanel del_panel = new JPanel();
// JLabel delname = new JLabel("DELETE FILE\nFile Name: ");
// JTextField deltf = new JTextField(10);
// del_panel.add(delname);
// del_panel.add(deltf);

// JButton delbutton = new JButton("Click to Delete File");
// del_panel.add(delbutton);

// //////////////// Add to the frame ///////////////
// frame.getContentPane().add(conn_panel);
// frame.getContentPane().add(login_panel);
// frame.getContentPane().add(reset_panel);
// frame.getContentPane().add(cu_panel);
// frame.getContentPane().add(du_panel);
// frame.getContentPane().add(cg_panel);
// frame.getContentPane().add(dg_panel);
// frame.getContentPane().add(agu_panel);
// frame.getContentPane().add(rgu_panel);
// frame.getContentPane().add(lm_panel);
// frame.getContentPane().add(lf_panel);
// frame.getContentPane().add(uf_panel);
// frame.getContentPane().add(df_panel);
// frame.getContentPane().add(del_panel);
// frame.getContentPane().add(ta);
// frame.getContentPane().add(exit);
// frame.pack();
// frame.setVisible(true);

// // connect with defaults
// defaults.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// giptf.setText(GIP);
// gporttf.setText(GPORT);
// fiptf.setText(FIP);
// fporttf.setText(FPORT);
// ta.setText("Connection with defaults...");
// connect(GIP, FIP, Integer.parseInt(GPORT), Integer.parseInt(FPORT));
// }
// });

// // connect with specified values.
// connect.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// GIP = giptf.getText();
// GPORT = gporttf.getText();
// FIP = fiptf.getText();
// FPORT = fporttf.getText();
// if(GIP.equals("") || FIP.equals("") || GPORT.equals("") || FPORT.equals("")){
// ta.setText("\nYou must enter all connection values (ips and ports).\n\n");
// GIP = "127.0.0.1";
// FIP = "127.0.0.1";
// GPORT = "8765";
// FPORT = "4321";
// return;
// }
// ta.setText("Connection with specified values...");
// connect(GIP, FIP, Integer.parseInt(GPORT), Integer.parseInt(FPORT));
// }
// });

// // login with username/Password
// loginbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String uname = ulogtf.getText();
// String pass = passlogtf.getText();
// ulogtf.setText("");
// passlogtf.setText("");
// login(uname, pass);
// }
// });

// // reset password
// resetbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String uname = uRestf.getText();
// String pass = rpasslogtf.getText();
// String npass = npasslogtf.getText();
// ulogtf.setText("");
// rpasslogtf.setText("");
// npasslogtf.setText("");
// resetPassword(uname, pass, npass);
// }
// });

// // Log out by removing token.
// logout.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// utkn = null;
// ta.setText("Logging out...\n");
// ta.append("Logged out successfully.\n\n");
// ta.append("Bye!\n\n\n");
// ta.append("Please log in.\n\n");
// }
// });

// //Disconnect and Exit
// exit.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// exit();
// }
// });

// // Create user button.
// cubutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String uname = cutf.getText();
// String pass = passcutf.getText();
// cutf.setText("");
// passcutf.setText("");
// createUser(uname, pass);
// }
// });

// // Delete user button.
// dubutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String uname = dutf.getText();
// dutf.setText("");
// deleteUser(uname);
// }
// });

// // Create group button.
// cgbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String gname = cgtf.getText();
// cgtf.setText("");
// createGroup(gname);
// }
// });

// // Delete group button.
// dgbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String gname = dgtf.getText();
// dgtf.setText("");
// deleteGroup(gname);
// }
// });

// // add group member button.
// agubutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String gname = agutf.getText();
// agutf.setText("");
// String uname = autf.getText();
// autf.setText("");
// addUserToGroup(uname, gname);
// }
// });

// // remove group member button.
// rgubutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String gname = rgutf.getText();
// rgutf.setText("");
// String uname = rutf.getText();
// rutf.setText("");
// deleteUserFromGroup(uname, gname);
// }
// });

// // list group members button.
// lmbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String gname = lmtf.getText();
// lmtf.setText("");
// listGroupMembers(gname);
// }
// });

// // list all files button.
// lfbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// listFiles();
// }
// });

// // upload file button.
// ufbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String ufname = ufutf.getText();
// ufutf.setText("");
// String dfname = ufdtf.getText();
// ufdtf.setText("");
// String gfname = ufgtf.getText();
// ufgtf.setText("");
// upload(ufname, dfname, gfname);
// }
// });

// // download file button.
// dfbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String ufname = dfutf.getText();
// dfutf.setText("");
// String dfname = dfdtf.getText();
// dfdtf.setText("");
// download(ufname, dfname);
// }
// });

// // delete file button.
// delbutton.addActionListener(new ActionListener(){
// public void actionPerformed(ActionEvent e){
// String dfname = deltf.getText();
// deltf.setText("");
// deleteFile(dfname);
// }
// });

// }

// private static void connect(String gip, String fip, int gport, int fport){
// boolean gconn = gcli.connect(gip, gport, "group");
// boolean fconn = fcli.connect(fip, fport, "file");
// if(!(gconn)){
// ta.setText("Error connecting to group server.");
// }
// if(!(fconn)){
// ta.setText("Error connecting to file server.");
// }
// else{
// ta.setText("Connected!\n");
// connected = true;
// }
// if(!loggedin) ta.append("Please log in.\n\n");
// else printMenu();
// }

// private static void printMenu(){
// ta.append("What would you like to do?\n");
// ta.append("You can complete the following operations: \n\n");
// ta.append("1. Create a new user\t");
// ta.append("2. Delete a user\t");
// ta.append("3. Create a new group\t");
// ta.append("4. Delete a group\n");
// ta.append("5. Add a user to a group\t");
// ta.append("6. Remove a user from a group\t");
// ta.append("7. List all members of a group\n");
// ta.append("8. List files\t");
// ta.append("9. Upload a file\t");
// ta.append("10. Download a file\t");
// ta.append("11. Delete a file\n");
// }

// private static boolean checkLogInStatus(){
// if(utkn == null){
// ta.setText("\nNo user session found. Please log in.\n\n");
// return false;
// }
// return true;
// }

// private static void login(String uname, String pass){
// if(!connected){
// ta.setText("Client not connected.\nPlease connect to group and file
// servers.\n\n");
// return;
// }
// ta.setText("\nLoggin in...\n");
// // TODO: Add password to this when we introduce password hashing.
// if(uname.equals("") || uname.equals(" ")){
// ta.setText("\nYou must enter a username.\n\nPlease try again.\n");
// return;
// }
// if(!gcli.userExists(uname)){
// //intentionally non-specific error message.
// ta.setText("Error logging in!\n\n");
// return;
// }
// // Check for password match
// ta.append("Verifying password...");
// if(!gcli.checkPassword(uname, pass)){
// //intentionally non-specific error message.
// ta.setText("Error logging in.\n\n");
// return;
// }
// if(gcli.firstLogin(uname)){
// ta.setText("It's your first time logging in. Please change your
// password.\n\n");
// ta.append("Please change your password using the \"PASSWORD RESET\" section
// in the GUI above.\n\n");
// return;
// }
// utkn = gcli.getToken(uname);
// if(utkn != null){
// ta.append("Logged in as " + utkn.getSubject() + "\n\n\n");
// loggedin = true;
// printMenu();
// }
// else{
// ta.append("Error loggin in...\nPlease try again\n\n\n");
// loggedin = false;
// return;
// }
// }

// private static void resetPassword(String uname, String pass, String npass){
// ta.setText("\nReset Password\n\n");
// if(gcli.checkPassword(uname, pass)){
// boolean reset = gcli.resetPassword(uname, npass);
// if(!reset) ta.append("An error occurred resetting user password!\n");
// else ta.append("User " + uname + " successfully reset password!\n\n\n");
// printMenu();
// }
// }

// private static void createUser(String uname, String pass){
// ta.setText("\nCreate a new user\n\n");
// if(checkLogInStatus()){
// boolean create = gcli.createUser(uname, pass, utkn);
// if(!create) ta.append("An error occurred creating user " + uname + "\n");
// else ta.append("User " + uname + " created successfully!\n\n\n");
// printMenu();
// }
// }

// private static void deleteUser(String uname){
// ta.setText("\nDelete a user\n\n");
// if(checkLogInStatus()){
// boolean delete = gcli.deleteUser(uname, utkn);
// if(!delete) ta.append("An error occurred deleting user " + uname + "\n");
// else ta.append("User " + uname + " deleted successfully!\n\n\n");
// printMenu();
// }
// }

// private static void createGroup(String gname){
// ta.setText("\nCreate a group\n");
// if(checkLogInStatus()){
// boolean Gcreate = gcli.createGroup(gname, utkn);
// if(!Gcreate) ta.append("An error occurred creating group " + gname +
// "\n\n\n");
// else ta.append("Group " + gname + " created successfully!\n\n\n");
// printMenu();
// }
// }

// private static void deleteGroup(String gname){
// ta.setText("\nCreate a group\n");
// if(checkLogInStatus()){
// boolean Gdelete = gcli.deleteGroup(gname, utkn);
// if(!Gdelete) ta.append("An error occurred deleting group " + gname +
// "\n\n\n");
// else ta.append("Group " + gname + " deleted successfully!\n\n\n");
// printMenu();
// }
// }

// private static void addUserToGroup(String uname, String gname){
// ta.setText("\nAdd a user to a group\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// boolean addToG = gcli.addUserToGroup(uname, gname, utkn);
// if(!addToG) ta.append("An error occurred adding user " + uname + " to group "
// + gname + "\n\n\n");
// else ta.append("User " + uname + " successfully added to " + gname +
// "!\n\n\n");
// printMenu();
// }
// }

// private static void deleteUserFromGroup(String uname, String gname){
// ta.setText("\nDelete a user form a group\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// boolean delToG = gcli.deleteUserFromGroup(uname, gname, utkn);
// if(!delToG) ta.append("An error occurred deleting user " + uname + " from
// group " + gname + "\n\n\n");
// else ta.append("User " + uname + " successfully deleted from " + gname +
// "!\n\n\n");
// printMenu();
// }
// }

// private static void listGroupMembers(String gname){
// ta.setText("\nList all members of a group\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// java.util.List<String> mems = gcli.listMembers(gname, utkn);
// if(mems == null) ta.append("An error occurred getting users from " + gname +
// ".\n\n\n");
// else {
// ta.append("Members in Group " + gname + ": \n");
// for(String mem: mems){
// ta.append(mem+"\n");
// }
// ta.append("\n\n\n");
// }
// printMenu();
// }
// }

// private static void listFiles(){
// ta.setText("\nList files\n");
// if(checkLogInStatus()){
// // FileThread should check the user's groups from the token
// // Bounce the token
// utkn = bounceToken();
// java.util.List<String> files = fcli.listFiles(utkn);
// ta.append("The files that user " + utkn.getSubject() + " can access are:
// \n\n\n");
// for(String f: files){
// ta.append(f+"\n");
// }
// ta.append("\n\n\n");
// printMenu();
// }
// }

// private static void upload(String upname, String dname, String group){
// ta.setText("\nUpload a file\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// if(!fcli.upload(upname, dname, group, utkn)) ta.append("Error uploading file
// to file server.\n\n\n");
// else ta.append("File successfully uploaded to file server!\n\n\n");
// printMenu();
// }
// }

// private static void download(String upname, String dname){
// ta.setText("\nDownload a file\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// if(!fcli.download(upname, dname, utkn)) ta.append("Error downloading
// file.\n\n\n");
// else ta.append("File successfully downloaded!\n\n\n");
// printMenu();
// }
// }

// private static void deleteFile(String fname){
// ta.setText("\nDelete a file\n");
// utkn = bounceToken();
// if(checkLogInStatus()){
// if(!fcli.delete(fname, utkn)) ta.append("Error deleting file from file
// server.\n\n\n");
// else ta.append("File successfully deleted from file server!\n\n\n");
// printMenu();
// }
// }

// private static void exit(){
// gcli.disconnect();
// fcli.disconnect();
// System.exit(0);
// }

// private static UserToken bounceToken(){
// // Bounce the server connections and re-login
// gcli.disconnect();
// gcli.connect(GIP, Integer.parseInt(GPORT), "group");
// fcli.disconnect();
// fcli.connect(FIP, Integer.parseInt(FPORT), "file");
// String uname = utkn.getSubject();
// return gcli.getToken(uname);
// }

// }
