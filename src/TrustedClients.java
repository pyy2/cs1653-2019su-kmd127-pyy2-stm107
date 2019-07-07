import java.util.*;
import java.security.*;

public class TrustedClients implements java.io.Serializable {
	private static final long serialVersionUID = 7600343803512547992L;
	protected Hashtable<String, PublicKey> pubkeys = new Hashtable<String, PublicKey>();

	public synchronized void addClient(String ip, PublicKey pubkey) {
		pubkeys.put(ip, pubkey);
	}
}
