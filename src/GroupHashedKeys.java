import java.util.*;

public class GroupHashedKeys implements java.io.Serializable {
  private static final long serialVersionUID = 6612343803512547992L;
  protected Hashtable<String, Hashtable<Integer, byte[]>> group_keys = new Hashtable<String, Hashtable<Integer, byte[]>>();

  public synchronized void addGroupKey(String group, int n, byte[] hash) {
    Hashtable<Integer, byte[]> key_table = new Hashtable<>();
    key_table.put(n, hash);
    group_keys.put(group, key_table);
  }

  public synchronized Hashtable<Integer, byte[]> getGroupKey(String group) {
    return group_keys.get(group);
  }

  public synchronized void removeGroupKey(String group) {
    group_keys.remove(group);
  }
}
