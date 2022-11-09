package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }


    public static void hexStringToByte(String hexString, byte[] message) {
        int index = 0;
        for (int i = 0; i < hexString.length(); i+=2) {
            // Using parseInt() method of Integer class
          int val = Integer.parseInt(hexString.substring(i, i + 2), 16);
          message[index++] = (byte)val;
      }
    }

    // hexstring with leading zeroes
    public static String integerToHexString(final int aValue, final int aFieldWidth) {
        // first build a mask to cut off the signed extension
        final long mask = (long) (Math.pow(16.0, aFieldWidth) - 1L);
    
        StringBuilder sb = new StringBuilder(Long.toHexString(aValue & mask));
    
        int numberOfLeadingZeros = Math.max(0, aFieldWidth - sb.length());
        for (; numberOfLeadingZeros > 0; numberOfLeadingZeros--) {
            sb.insert(0, '0');
        }
    
        return sb.toString();
      }

    public static String hostNameToHexString(String hostName){
        String hexString = "";
        String[] parts = hostName.split("\\.");
        for (String s: parts){
            hexString += integerToHexString(s.length(), 2);
            for (char c : s.toCharArray()){
              hexString += Integer.toHexString(c);
            }
        }
        // Add 00 to indicate end
        hexString += "00";
        return hexString;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {

        // Query ID (16 bit), generated randomly
        int queryID = random.nextInt(65535);
        String queryHex = integerToHexString(queryID, 4);

        // QR (1) = 0, Opcode (4) = 0000, AA (1) = 0, TC (1) = 0, RD (1) = 0
        // 00 00 00 00 = 00 (hex)
        
        // RA (1) = 0, Z (3) = 000, RCODE (4) = 0000
        // 00 00 00 00 = 00 (hex)
        
        // Query Count (16 bits)
        // 00 01 (hex)

        // Answer Count (16 bits)
        // 00 00 (hex)

        // Nameserver Records count (16 bits)
        // 00 00 (hex)
        
        // Additional Records count (16 bits)
        // 00 00 (hex)

        // Adds hexstring to queryHex as above
        queryHex += "00000001000000000000";
        
        // Qname Start (0 byte to indicate end)
        String hostname = node.getHostName();
        queryHex += hostNameToHexString(hostname);
        
        // Qtype (16 bits)
        int qType = node.getType().getCode();
        queryHex += integerToHexString(qType, 4);
        
        // Qclass (16 bits)
        // Internet (01)
        queryHex += "0001";
        
        hexStringToByte(queryHex, message);
        
        byte[] query = Arrays.copyOfRange(message, 0, queryHex.length()/2);

        DatagramPacket packet = new DatagramPacket(query, query.length, server, DEFAULT_DNS_PORT);
        byte[] response = new byte[1024];
        DatagramPacket packetReceived = new DatagramPacket(response, response.length);

        try {
            if (verboseTracing) {
                System.out.println("\n");
                System.out.printf("Query ID     %d %s  %s --> %s\n", queryID, hostname, node.getType(), server.toString().substring(1));
            }
            socket.send(packet);
            socket.receive(packetReceived);

        } catch (SocketTimeoutException se) {
            // send again in event of timeout
            try {
                if (verboseTracing) {
                    System.out.println("\n");
                    System.out.printf("Query ID     %d %s  %s --> %s\n", queryID, hostname, node.getType(), server.toString().substring(1));
                }
                socket.receive(packet);
            } catch (Exception e) {
                byte[] emptyResponse = new byte[1024];
                return new DNSServerResponse(ByteBuffer.wrap(emptyResponse), queryID);
            }
        }

        packetReceived.getData();

        // wrap response in ByteBuffer and save to DNSServerResponse
        ByteBuffer buffer = ByteBuffer.wrap(packetReceived.getData());
        DNSServerResponse dnsResponse = new DNSServerResponse(buffer, queryID);
        // System.out.println(dnsResponse);
        return dnsResponse;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     * @throws IOException
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) throws IOException {

        DNSResponseDecoder decoder =  new DNSResponseDecoder(responseBuffer, verboseTracing);
        decoder.decodeResponse();
        Set<ResourceRecord> ResourceRecords = decoder.getResourceRecords();

        // Add all decoded ResourceRecords to cache
        for (ResourceRecord r : ResourceRecords) {
            cache.addResult(r);
        }

        if (!ResourceRecords.isEmpty()){
            return ResourceRecords;
        }
        else {
            return null;
        }
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

