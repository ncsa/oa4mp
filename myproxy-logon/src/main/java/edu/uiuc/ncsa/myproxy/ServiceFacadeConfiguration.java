package edu.uiuc.ncsa.myproxy;


import java.util.Map;

/**
 * Properties for the MyProxyService facade. This supports a configurable hostname and various levels of
 * assurance.
 * <p>Created by Jeff Gaynor<br>
 * on May 14, 2010 at  10:16:44 AM
 */
public class ServiceFacadeConfiguration {
    /**
     * Sets the name of the server and default port. The levels of assurance as passed as
     * a map of strings and port numbers. A call for a specific level of assurance will
     * simply look up the port number and use that. This allows for changing the LOA
     * port numbers in the configuration rather than having to worry about coding them.
     *
     * @param hostname Fully qualified name of the MyProxy server
     * @param port     The port for the server
     * @param loas     A map consisting of the level of assurance names and port numbers.
     */
    public ServiceFacadeConfiguration(String hostname, int port, long socketTimeout, Map<String, Integer> loas, String serverDN) {
        this.hostname = hostname;
        this.loas = loas;
        this.port = port;
        this.socketTimeout = socketTimeout;
        this.serverDN = serverDN;
    }

    /**
     * Constructor for the case that no serverDN is specified. in that case, the trust manager will simply verify the
     * server DN found from the server cert.
     * @param hostname
     * @param port
     * @param socketTimeout
     * @param loas
     */
    public ServiceFacadeConfiguration(String hostname, int port, long socketTimeout, Map<String, Integer> loas) {
        this(hostname, port, socketTimeout, loas, null);
    }

    Map<String, Integer> loas;
    long socketTimeout = 0L;
    String hostname;
    int port = -1;

    public String getServerDN() {
        return serverDN;
    }

    String serverDN = null;

    /**
     * Get the fully qualified hostname for the MyProxy server
     *
     * @return
     */
    public String getHostname() {
        return hostname;
    }


    /**
     * Get the port for the MyProxy Server.
     *
     * @return
     */
    public int getPort() {
        return port;
    }

    public long getSocketTimeout() {
        return socketTimeout;
    }
}
