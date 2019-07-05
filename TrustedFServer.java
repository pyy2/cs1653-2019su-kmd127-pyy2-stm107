import java.util.*;
import java.security.*;


	public class TrustedFServer implements java.io.Serializable {
    private static final long serialVersionUID = 7612343803512547992L;
		protected Hashtable<String, PublicKey> pubkeys = new Hashtable<String, PublicKey>();

    public synchronized void addServer(String ip, PublicKey pubkey)
		{
			pubkeys.put(ip, pubkey);
		}
  }
