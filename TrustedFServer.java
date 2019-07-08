import java.util.*;
import java.security.*;


	public class TrustedFServer implements java.io.Serializable {
    private static final long serialVersionUID = 7612343803512547992L;
		protected Hashtable<String, List<PublicKey>> pubkeys = new Hashtable<String, List<PublicKey>>();

    public synchronized void addServer(String ip, PublicKey pubkey)
		{
			if(pubkeys.get(ip) == null){
				List<PublicKey> pk_list = new ArrayList<PublicKey>();
				pk_list.add(pubkey);
				pubkeys.put(ip, pk_list);
			}
			else{
				pubkeys.get(ip).add(pubkey);
			}
		}
  }
