package at.tugraz.netguard;

public class ACNPacket {
    public long time;
    public int version;
    public String daddr;
    public int dport;
    public int uid;
    public String[] keywords;
    public int cipherSuite;
    public int tlsVersion;
    public int tlsCompression;

    public ACNPacket() {
    }

    @Override
    public String toString() {
        return "uid=" + uid + " v" + version + " " + daddr + "/" + dport +
                " kwords=" + ((keywords == null) ? 0 : keywords.length) + " cs=0x" + Integer.toHexString(cipherSuite) +
                " tlsV=0x" + Integer.toHexString(tlsVersion) + " tlsC=" + tlsCompression;
    }

    public int getNumKeywords()
    {
        return (keywords == null) ? 0 : keywords.length;
    }
}
