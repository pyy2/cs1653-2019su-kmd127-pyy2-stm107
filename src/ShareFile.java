public class ShareFile implements java.io.Serializable, Comparable<ShareFile> {

	/**
	 *
	 */
	private static final long serialVersionUID = -6699986336399821598L;
	private String group;
	private String path;
	private String owner;
	private int n;
	private byte[] hash;

	public ShareFile(String _owner, String _group, String _path, int _n, byte[] _hash) {
		group = _group;
		owner = _owner;
		path = _path;
		n = _n;
		hash = _hash;
	}

	public String getPath()
	{
		return path;
	}

	public String getOwner()
	{
		return owner;
	}

	public String getGroup() {
		return group;
	}

	public int getN(){
		return n;
	}

	public byte[] getHash(){
		return hash;
	}

	public int compareTo(ShareFile rhs) {
		if (path.compareTo(rhs.getPath())==0)return 0;
		else if (path.compareTo(rhs.getPath())<0) return -1;
		else return 1;
	}


}
