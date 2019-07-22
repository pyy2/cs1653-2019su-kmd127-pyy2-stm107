import java.util.*;

public class GroupSeeds implements java.io.Serializable {
  private static final long serialVersionUID = 5612343803512547992L;
  protected Hashtable<String, byte[]> seeds = new Hashtable<String, byte[]>();

  public synchronized void addSeed(String group, byte[] seed) {
    seeds.put(group, seed);
  }

  public synchronized byte[] getSeed(String group) {
    return seeds.get(group);
  }

  public synchronized void removeSeed(String group) {
    seeds.remove(group);
  }
}
