import java.util.List;

/**
 * A simple interface to the token data structure that will be returned by a
 * group server.
 *
 * You will need to develop a class that implements this interface so that your
 * code can interface with the tokens created by your group server.
 *
 */
public class Token implements UserToken, java.io.Serializable {

  // GroupThread.java line 157 -- Constructor implementation
  // UserToken yourToken = new Token(my_gs.name, username,
  // my_gs.userList.getUserGroups(username));
  private static final long serialVersionUID = -8911161283900260245L;
  private String issuer;
  private String subject;
  private List<String> groups;
  private long creationTime;
  private long expirationTime;


  public Token(String _issuer, String _subject, List<String> _groups, long _creationTime, long _expirationTime) {
    issuer = _issuer;
    subject = _subject;
    groups = _groups;
    creationTime = _creationTime;
    expirationTime = _expirationTime;
  }

  /**
   * This method should return a string describing the issuer of this token. This
   * string identifies the group server that created this token. For instance, if
   * "Alice" requests a token from the group server "Server1", this method will
   * return the string "Server1".
   *
   * @return The issuer of this token
   *
   */
  public String getIssuer() {
    return issuer;
  }

  /**
   * This method should return a string indicating the name of the subject of the
   * token. For instance, if "Alice" requests a token from the group server
   * "Server1", this method will return the string "Alice".
   *
   * @return The subject of this token
   *
   */
  public String getSubject() {
    return subject;
  }

  /**
   * This method extracts the list of groups that the owner of this token has
   * access to. If "Alice" is a member of the groups "G1" and "G2" defined at the
   * group server "Server1", this method will return ["G1", "G2"].
   *
   * @return The list of group memberships encoded in this token
   *
   */
  public List<String> getGroups() {
    return groups;
  }

  public long getEXPtime(){
    return expirationTime;
  }

  public long getCREtime(){
    return creationTime;
  }

  public String toString() {
    String tokenString = issuer + ";" + subject + ";" + creationTime + ";" + expirationTime + ";";
    
    for (int i = 0; i < groups.size(); i++) {
      tokenString += groups.get(i);
      if (i != groups.size() - 1) {
        tokenString += ";";
      }

    }

    return tokenString;
  }

} // -- end interface UserToken
