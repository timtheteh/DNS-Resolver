package ca.ubc.cs317.dnslookup;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class DNSResponseDecoder {

  private byte[] byteArray;
  private DataInputStream data;
  private boolean verboseTracing;

  Set<ResourceRecord> resourceRecords;
  HashMap<Integer, String> pointerDict = new HashMap<Integer, String>();

  /**
   * Constructor for DNS Response Decoder
   * @param buffer ByteBuffer of byte array response from query
   * @param verboseTracing Whether trace is on or off
   */
  public DNSResponseDecoder(ByteBuffer buffer, boolean verboseTracing) {
    this.byteArray = buffer.array();
    this.data = new DataInputStream(new ByteArrayInputStream(byteArray));
    this.resourceRecords = new HashSet<ResourceRecord>();
    this.verboseTracing = verboseTracing;
  }

  /**
   * Retrieves all saved ResourceRecords
   * @return set of resouce records
   */
  public Set<ResourceRecord> getResourceRecords() {
    return resourceRecords;
  }

  /**
   * Parses whole response including flags etc.
   * @throws IOException
   */
  public void decodeResponse() throws IOException {

    // transaction ID
    byte transactionid1 = data.readByte();
    byte transactionid2 = data.readByte();

    int transactionid = ((transactionid1 & 0xff) << 8) | ((transactionid2 & 0xff) << 0);

    // flags 1
    short flags = data.readByte();
    boolean isAuthoritative = (flags & 0b00000100) >>> 2 == 1;

    // flags 2
    data.readByte();

    // reads number of questions
    data.readShort();
    int numAnswers = data.readShort();
    int numAuths = data.readShort();
    int numAdds = data.readShort();

    // gets query hostname
    getDomain();

    // Read QTYPE
    data.readShort();
    // Read QCLASS
    data.readShort();

    if(verboseTracing){
      System.out.printf("Response ID: %d Authoritative = %s\n", transactionid, isAuthoritative);
    }

    // parse answers
    if (verboseTracing) {
      System.out.println("Answers (" + numAnswers + ")");
    }

    for (int i = 0; i < numAnswers; i++){
      parseRecord();
    }

    // parse authority section
    if (verboseTracing) {
      System.out.println("Nameservers (" + numAuths + ")");
    }

    for (int i = 0; i < numAuths; i++){
      parseRecord();
    }

    // parse additional records section
    if (verboseTracing) {
      System.out.println("Additional Information (" + numAdds + ")");
    }

    for (int i = 0; i < numAdds; i++){
      parseRecord();
    }
    
  }

  /**
   * Parses a record by its respective type
   * @throws IOException
   */
  private void parseRecord() throws IOException {
		String host = "";
		RecordType type = null;
		long ttl = 0;
		String result = "";
		InetAddress ip = null;

		host = getDomain();

		type = RecordType.getByCode(data.readShort());
     // response class
		data.readShort();
		ttl = data.readInt();

		int length = data.readShort();

		switch (type) {
			// IPv4 address
			case A:
				byte[] addr4 = new byte[length];
				for (int i = 0; i < length; i++) {
					addr4[i] = data.readByte();
				}
				ip = InetAddress.getByAddress(host, addr4);
				break;
			// IPv6 address
			case AAAA:
				byte[] addr6 = new byte[16];
				for (int i = 0; i < 16; i++) {
					addr6[i] = data.readByte();
				}
				ip = InetAddress.getByAddress(host, addr6);
				break;
			case NS:
			case CNAME:
				result = getDomain();
				break;
			// if any other type, do nothing
			default:
				break;
		}

		ResourceRecord record;
		if (ip != null) {
			record = new ResourceRecord(host, type, ttl, ip);
      result = ip.getHostAddress();
		} else {
			record = new ResourceRecord(host, type, ttl, result);
		}
    if (verboseTracing) {
      if (result.equals("")) {
          result = "----";
      }
      System.out.printf("       %-30s %-10d %-4s %s\n", host, ttl, type, result);
  }
    resourceRecords.add(record);
	}

  public String getDomain() throws IOException {
    String domain = "";
    StringBuilder sb = new StringBuilder();
    int firstByte = data.readByte();
    int nextByte = firstByte;
    int offset;

    if (isPointer(firstByte)){
      // find offset
      offset = Byte.toUnsignedInt(data.readByte());
      if (pointerDict.containsKey(offset)) {
        return pointerDict.get(offset);
			}
      domain = getDomainFromPointer(offset);
      return domain;
    }

    // until terminating 0 or another pointer, parse to String
    while (nextByte > 0 && !isPointer(nextByte)) {
      int partLen = nextByte;
			byte[] domainParts = new byte[partLen];
			for (int i = 0; i < partLen; i++) {
				domainParts[i] = data.readByte();
			}
			String domainPart = new String(domainParts);
			sb.append(domainPart);
      sb.append(".");
			nextByte = data.readByte();
		}

    // remove . at end
    if (sb.length() > 0){
      sb.deleteCharAt(sb.length()-1);
    }

    // if it ends in pointer, follow it
    if (isPointer(nextByte)) {
			offset = Byte.toUnsignedInt(data.readByte());
      sb.append(".");
      sb.append(getDomainFromPointer(offset));
		}

    domain = sb.toString();
    return domain;
  }

  public String getDomainFromPointer(int offset) throws IOException {

    // if pointer has already been found, just fetch
    if (pointerDict.containsKey(offset)) {
      return pointerDict.get(offset);
    }

    int index = offset;
    
    StringBuilder sb = new StringBuilder();
    
    // same as in normal parse, just reading by index rather than a datastream
    while (byteArray[index] != 0  && !isPointer(byteArray[index])) {
      int len = byteArray[index];
      String domainPart = new String(Arrays.copyOfRange(byteArray, (index+1), (index+len+1)), StandardCharsets.UTF_8);
      index+=len + 1;
      sb.append(domainPart);
      sb.append(".");
    }
    if (sb.length() > 0){
      sb.deleteCharAt(sb.length()-1);
    }
    
    if (isPointer(byteArray[index])){
      sb.append(".");
      sb.append(getDomainFromPointer(Byte.toUnsignedInt(byteArray[index + 1])));
    }
    
    String finalDomain = sb.toString();

    // add any found compressions to a dictionary
    pointerDict.put(offset, finalDomain);
    return finalDomain;
  }

  /**
   * Checks if the first byte is a pointer
   * @param firstByte
   * @return True if the it is a pointer
   */
  public boolean isPointer(int firstByte) {
    return ((firstByte & 0xff) == 192);
  }

}
