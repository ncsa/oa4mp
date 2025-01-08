/*
 * Copyright 2007 The Board of Trustees of the University of Illinois.
 * All rights reserved.
 * 
 * Developed by:
 * 
 *   MyProxy Team
 *   National Center for Supercomputing Applications
 *   University of Illinois
 *   http://myproxy.ncsa.uiuc.edu/
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal with the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimers.
 * 
 *   Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimers in the
 *   documentation and/or other materials provided with the distribution.
 * 
 *   Neither the names of the National Center for Supercomputing
 *   Applications, the University of Illinois, nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this Software without specific prior written permission.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH THE SOFTWARE.
 */
package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.HostUtil;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.ssl.MyTrustManager;
import org.apache.commons.codec.binary.Base64;

import javax.net.ssl.*;
import javax.security.auth.login.FailedLoginException;
import java.io.*;
import java.net.ProtocolException;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.logging.Logger;


/**
 * The MyProxyLogon class provides an interface for retrieving credentials from
 * a MyProxy server.
 * <p/>
 * First, use
 * <code>
 * <ul>
 * <li>setHost</li>
 * <li>setPort</li>
 * <li>setUsername</li>
 * <li>setPassphrase</li>
 * <li>setCredentialName</li>
 * <li>setLifetime</li>
 * <li>requestTrustRoots</li>
 * </ul>
 * </code>
 * to configure. Then call
 * <code>
 * <ul>
 * <li>logon</li>
 * <li>getCredentials</li>
 * <li>disconnect</li>
 * </ul>
 * </code>
 * Use <code>getCertificates</code> and
 * <code>getPrivateKey</code> to access the retrieved credentials, or
 * <code>writeProxyFile</code> or <code>saveCredentialsToFile</code> to
 * write them to a file. Use <code>writeTrustRoots</code>,
 * <code>getTrustedCAs</code>, <code>getCRLs</code>,
 * <code>getTrustRootData</code>, and <code>getTrustRootFilenames</code>
 * for trust root information.
 *
 * @version 1.6
 * @see <a href="http://myproxy.ncsa.uiuc.edu/">MyProxy Project Home Page</a>
 */
public class MyProxyLogon {
    public MyLoggingFacade getMlf() {
        return mlf;
    }

    MyLoggingFacade mlf = null;
  //  public final static String version = "1.8";

    protected enum State {
        READY, CONNECTED, LOGGEDON, DONE
    }

    long socketTimeout = 0L;

    private final static int b64linelen = 64;
    private final static String X509_USER_PROXY_FILE = "x509up_u";
    private final static String VERSION = "VERSION=MYPROXYv2";
    private final static String GETCOMMAND = "COMMAND=0";
    private final static String TRUSTROOTS = "TRUSTED_CERTS=";
    private final static String USERNAME = "USERNAME=";
    private final static String PASSPHRASE = "PASSPHRASE=";
    private final static String LIFETIME = "LIFETIME=";
    private final static String CREDNAME = "CRED_NAME=";
    private final static String RESPONSE = "RESPONSE=";
    private final static String ERROR = "ERROR=";
    private final static String DN = "CN=ignore";
    private final static String TRUSTED_CERT_PATH = "/.globus/certificates";

    public final int DEFAULT_KEY_SIZE = 2048;
    protected int keySize = DEFAULT_KEY_SIZE;
    protected final int MIN_PASS_PHRASE_LEN = 6;
    protected final static String keyAlg = "RSA";
    protected final static String pkcs10SigAlgName = "SHA1withRSA";
    protected final static String pkcs10Provider = "BC";
    protected State state = State.READY;
    protected String host = "localhost";
    protected String username;
    protected String credname;
    protected String passphrase;
    protected int port = 7512;
    protected int lifetime = 43200;
    protected boolean requestTrustRoots = false;
    protected SSLSocket socket;
    protected BufferedInputStream socketIn;
    protected BufferedOutputStream socketOut;
    protected KeyPair keypair;
    protected Collection<X509Certificate> certificateChain;
    protected String[] trustrootFilenames;
    protected String[] trustrootData;
    KeyManagerFactory keyManagerFactory;

    /**
     * Set the socket timeout (in milliseconds) for this connection. If this is not set,
     * then this is equivalent to setting it to 0, which in turn means that whatever the
     * system default is will be used.
     *
     * @return
     */
    public long getSocketTimeout() {
        return socketTimeout;
    }

    public void setSocketTimeout(long socketTimeout) {
        this.socketTimeout = socketTimeout;
    }

    public MyProxyLogon(MyLoggingFacade myLoggingFacade) {
        super();
        this.mlf = myLoggingFacade;
    }

    public MyProxyLogon(MyLoggingFacade myLoggingFacade, String serverDN) {
        super();
        this.mlf = myLoggingFacade;
        this.serverDN = serverDN;
    }

    /**
     * Constructs a MyProxyLogon object.  This turns off any logging, so only use this
     * constructor if you need to do that. Otherwise, inject your favorite logger wrapped
     * in an {@link MyLoggingFacade} object.
     */
    public MyProxyLogon() {
        super();
        Logger logger = Logger.getLogger(MyProxyLogon.class.getName());
        logger.setUseParentHandlers(false);
        MyLoggingFacade facade = new MyLoggingFacade(logger);
        this.mlf = facade;


        host = System.getenv("MYPROXY_SERVER");
        if (host == null) {
            host = "localhost";
        }
        String portString = System.getenv("MYPROXY_SERVER_PORT");
        if (portString != null) {
            port = Integer.parseInt(portString);
        }
        username = System.getProperty("user.name");
    }

    /**
     * Gets the hostname of the MyProxy server.
     *
     * @return MyProxy server hostname
     */
    public String getHost() {

        return this.host;
    }

    /**
     * This is the *real* host. The user may set the host property but this should be used internally
     * since it will do any reverse lookups needed.
     *
     * @return
     * @throws UnknownHostException
     */
    protected String hostLookup() throws UnknownHostException {
        return HostUtil.canonicalName(getHost());
    }


    /**
     * Sets the hostname of the MyProxy server. Defaults to localhost.
     *
     * @param host MyProxy server hostname
     */
    public void setHost(String host) {
        this.host = host;
    }


    /**
     * Gets the port of the MyProxy server.
     *
     * @return MyProxy server port
     */
    public int getPort() {
        return this.port;
    }

    /**
     * Sets the port of the MyProxy server. Defaults to 7512.
     *
     * @param port MyProxy server port
     */
    public void setPort(int port) {
        this.port = port;
    }

    /**
     * Gets the key size. If this has not been set, it will be set to the default
     *
     * @return MyProxy key size
     */
    public int getKeySize() {
        return keySize;
    }

    /**
     * Sets the key size.
     *
     * @param keySize
     */

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    /**
     * Gets the MyProxy username.
     *
     * @return MyProxy server port
     */
    public String getUsername() {
        return this.username;
    }

    /**
     * Sets the MyProxy username. Defaults to user.name.
     *
     * @param username MyProxy username
     */
    public void setUsername(String username) {
        this.username = username;
    }

    /**
     * Gets the optional MyProxy credential name.
     *
     * @return credential name
     */
    public String getCredentialName() {
        return this.credname;
    }

    /**
     * Sets the optional MyProxy credential name.
     *
     * @param credname credential name
     */
    public void setCredentialName(String credname) {
        this.credname = credname;
    }

    /**
     * Sets the MyProxy passphrase.
     *
     * @param passphrase MyProxy passphrase
     */
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    /**
     * Gets the requested credential lifetime.
     *
     * @return Credential lifetime
     */
    public int getLifetime() {
        return this.lifetime;
    }

    /**
     * Sets the requested credential lifetime. Defaults to 43200 seconds (12
     * hours).
     *
     * @param seconds Credential lifetime
     */
    public void setLifetime(int seconds) {
        this.lifetime = seconds;
        if (this.lifetime < 0) {
            getMlf().warn("Negative cert lifetime of " + this.lifetime + " encountered. Server should default to 0.");
        }
    }

    /**
     * Gets the certificates returned from the MyProxy server by
     * getCredentials().
     *
     * @return Collection of java.security.cert.Certificate objects
     */
    public Collection<X509Certificate> getCertificates() {
        return this.certificateChain;
    }

    /**
     * Gets the private key generated by getCredentials().
     *
     * @return PrivateKey
     */
    public PrivateKey getPrivateKey() {
        return this.keypair.getPrivate();
    }

    /**
     * Sets whether to request trust roots (CA certificates, CRLs, signing
     * policy files) from the MyProxy server. Defaults to false (i.e., not
     * to request trust roots).
     *
     * @param flag If true, request trust roots. If false, don't request trust
     *             roots.
     */
    public void requestTrustRoots(boolean flag) {
        this.requestTrustRoots = flag;
    }

    /**
     * Gets trust root filenames.
     *
     * @return trust root filenames
     */
    public String[] getTrustRootFilenames() {
        return this.trustrootFilenames;
    }

    /**
     * Gets trust root data corresponding to the trust root filenames.
     *
     * @return trust root data
     */
    public String[] getTrustRootData() {
        return this.trustrootData;
    }

    /**
     * This will be used against the server's DN by the trust manager when checking the certificate. This
     * allows for setting a single DN across a set of servers (e.g. for load balancing).
     *
     * @return
     */
    public String getServerDN() {
        return serverDN;
    }

    public void setServerDN(String serverDN) {
        this.serverDN = serverDN;
    }

    String serverDN = null;

    /**
     * Connects to the MyProxy server at the desired host and port. Requires
     * host authentication via SSL. The host's certificate subject must
     * match the requested hostname. If CA certificates are found in the
     * standard GSI locations, they will be used to verify the server's
     * certificate. If trust roots are requested and no CA certificates are
     * found, the server's certificate will still be accepted.
     */

    public void connect() throws IOException, GeneralSecurityException {
        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            MyTrustManager mtm = new MyTrustManager(getMlf(), getExistingTrustRootPath(), getServerDN());
            mtm.setHost(hostLookup());
            TrustManager[] trustAllCerts = new TrustManager[]{mtm};
            sc.init(getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory sf = sc.getSocketFactory();
            this.socket = (SSLSocket) sf.createSocket(this.hostLookup(), this.port);
            if (0 < getSocketTimeout()) {
                // NOTE that this is an integer that is used for milliseconds.
                socket.setSoTimeout((int) getSocketTimeout());
                socket.setKeepAlive(true);
            }
            this.socket.startHandshake();
            this.socketIn = new BufferedInputStream(this.socket.getInputStream());
            this.socketOut = new BufferedOutputStream(this.socket.getOutputStream());
            this.state = State.CONNECTED;
        } catch (Throwable t) {
            handleException(t, getClass().getSimpleName() + " could not connect to the server, socket " + (this.socket == null ? "" : "not") + " created.");
        }
    }

    protected void handleException(Throwable t, String msg) throws IOException, GeneralSecurityException {
        if (t instanceof SSLHandshakeException) {
            throw new GeneralException("Error connecting to server:" + t.getMessage(), t);
        }
        if (t instanceof IOException) {
            throw (IOException) t;
        }
        if (t instanceof GeneralSecurityException) {
            throw (GeneralSecurityException) t;
        }

        throw new GeneralSecurityException(" " + msg, t);
    }

    /**
     * Get the key manager factory set by setKeyManagerFactory().
     *
     * @return KeyManagerFactory
     */
    public KeyManagerFactory getKeyManagerFactory() {
        return keyManagerFactory;
    }

    /**
     * Set the key manager factory for use in client-side SSLSocket
     * certificate-based authentication to the MyProxy server.
     * Call this before connect().
     *
     * @param keyManagerFactory Key manager factory to use
     */
    public void setKeyManagerFactory(KeyManagerFactory keyManagerFactory) {
        this.keyManagerFactory = keyManagerFactory;
    }


    /**
     * Internal method that returns the KeyManagers for a KeyManagerFactory or a null if no KeyManagerFactory is set.
     *
     * @return
     */
    KeyManager[] getKeyManagers() {
        if (getKeyManagerFactory() == null) {
            return null;
        }
        return getKeyManagerFactory().getKeyManagers();
    }

    /**
     * Disconnects from the MyProxy server.
     */
    public void disconnect() throws IOException, GeneralSecurityException {
        try {
            this.socket.close();
            this.socket = null;
            this.socketIn = null;
            this.socketOut = null;
            this.state = State.READY;
        } catch (Throwable t) {
            handleException(t, getClass().getSimpleName() + " could not disconnect from the server, socket " + (this.socket == null ? "" : "not") + " created");
        }
    }


    /**
     * Logs on to the MyProxy server by issuing the MyProxy GET command.
     */
    public void logon() throws IOException, GeneralSecurityException {
        String line;
        char response;

        if (this.state != State.CONNECTED) {
            this.connect();
        }
        try {
            this.socketOut.write('0');
            this.socketOut.flush();
            this.socketOut.write(VERSION.getBytes());
            this.socketOut.write('\n');
            this.socketOut.write(GETCOMMAND.getBytes());
            this.socketOut.write('\n');
            this.socketOut.write(USERNAME.getBytes());
            this.socketOut.write(this.username.getBytes());
            this.socketOut.write('\n');
            this.socketOut.write(PASSPHRASE.getBytes());
            this.socketOut.write(this.passphrase.getBytes());
            this.socketOut.write('\n');
            this.socketOut.write(LIFETIME.getBytes());
            this.socketOut.write(Integer.toString(this.lifetime).getBytes());
            this.socketOut.write('\n');
            if (this.credname != null) {
                this.socketOut.write(CREDNAME.getBytes());
                this.socketOut.write(this.credname.getBytes());
                this.socketOut.write('\n');
            }
            if (this.requestTrustRoots) {
                this.socketOut.write(TRUSTROOTS.getBytes());
                this.socketOut.write("1\n".getBytes());
            }
            this.socketOut.flush();

            line = readLine(this.socketIn);
            if (line == null) {
                throw new EOFException();
            }
            if (!line.equals(VERSION)) {
                throw new ProtocolException("bad MyProxy protocol VERSION string: "
                        + line);
            }
            line = readLine(this.socketIn);
            if (line == null) {
                throw new EOFException();
            }
            if (!line.startsWith(RESPONSE)
                    || line.length() != RESPONSE.length() + 1) {
                throw new ProtocolException(
                        "bad MyProxy protocol RESPONSE string: " + line);
            }
            response = line.charAt(RESPONSE.length());
            if (response == '1') {
                StringBuffer errString;

                errString = new StringBuffer("MyProxy logon failed");
                while ((line = readLine(this.socketIn)) != null) {
                    if (line.startsWith(ERROR)) {
                        errString.append('\n');
                        errString.append(line.substring(ERROR.length()));
                    }
                }
                throw new FailedLoginException(errString.toString());
            } else if (response == '2') {
                throw new ProtocolException(
                        "MyProxy authorization RESPONSE not implemented");
            } else if (response != '0') {
                throw new ProtocolException(
                        "unknown MyProxy protocol RESPONSE string: " + line);
            }
            while ((line = readLine(this.socketIn)) != null) {
                if (line.startsWith(TRUSTROOTS)) {
                    String filenameList = line.substring(TRUSTROOTS.length());
                    this.trustrootFilenames = filenameList.split(",");
                    this.trustrootData = new String[this.trustrootFilenames.length];
                    for (int i = 0; i < this.trustrootFilenames.length; i++) {
                        String lineStart = "FILEDATA_" + this.trustrootFilenames[i]
                                + "=";
                        line = readLine(this.socketIn);
                        if (line == null) {
                            throw new EOFException();
                        }
                        if (!line.startsWith(lineStart)) {
                            throw new ProtocolException(
                                    "bad MyProxy protocol RESPONSE: expecting "
                                            + lineStart + " but received " + line);
                        }
                        this.trustrootData[i] = new String(Base64.decodeBase64(line
                                .substring(lineStart.length())));
                    }
                }
            }
            this.state = State.LOGGEDON;
        } catch (Throwable t) {
            handleException(t, getClass().getSimpleName() + " logon failed.");
        }
    }

    public void getCredentials(byte[] derEncodedCertRequest) throws IOException, GeneralSecurityException {
        try {

            if (this.state != State.LOGGEDON) {
                this.logon();
            }

            this.socketOut.write(derEncodedCertRequest);
            this.socketOut.flush();

            int numCertificates = this.socketIn.read();
            if (numCertificates == -1) {
                System.err.println("connection aborted");
                throw new IOException(" connection aborted");
            } else if (numCertificates == 0 || numCertificates < 0) {
                System.err.print("bad number of certificates sent by server: ");
                System.err.println(Integer.toString(numCertificates));
                throw new GeneralSecurityException(" bad number of certificates sent by server");
            }
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            this.certificateChain = (Collection<X509Certificate>) certFactory.generateCertificates(this.socketIn);
            this.state = State.DONE;
        } catch (Throwable t) {
            handleException(t, getClass().getSimpleName() + " failure getting the credential.");
        }
    }

    /**
     * Retrieves credentials from the MyProxy server.
     */
    public void getCredentials() throws IOException, GeneralSecurityException {
        KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(keyAlg);
        keyGenerator.initialize(getKeySize());
        this.keypair = keyGenerator.genKeyPair();
        MyPKCS10CertRequest pkcs10 = CertUtil.createCertRequest(this.keypair, pkcs10SigAlgName, DN);
        getCredentials(pkcs10.getEncoded());
    }

    /**
     * Writes the retrieved credentials to the Globus proxy file location.
     */
    public void writeProxyFile() throws IOException, GeneralSecurityException {
        saveCredentialsToFile(getProxyLocation());
    }

    /**
     * Writes the retrieved credentials to the specified output stream.
     *
     * @param os OutputStream to write to
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public void saveCredentials(OutputStream os) throws IOException, GeneralSecurityException {
        CertUtil.toPEM(certificateChain, os);
        // since we are putting the private key in the same file as the certs, we have to
        // add a new line.
        os.write('\n');
        KeyUtil.toPKCS8PEM(keypair.getPrivate(), os);
    }

    public X509Certificate getCertificate() {
        if (certificateChain == null) {
            return null;
        }
        Iterator<X509Certificate> iter = this.certificateChain.iterator();
        return iter.next();
    }

    /**
     * Writes the retrieved credentials to the specified filename.
     */
    public void saveCredentialsToFile(String filename) throws IOException,
            GeneralSecurityException {
        File outFile = new File(filename);
        outFile.delete();
        outFile.createNewFile();
        setFilePermissions(filename, "0600");
        FileOutputStream fos = new FileOutputStream(outFile);
        saveCredentials(fos);
        fos.flush();
        fos.close();
    }

    /**
     * Writes the retrieved trust roots to the Globus trusted certificates
     * directory.
     *
     * @return true if trust roots are written successfully, false if no
     * trust roots are available to be written
     */
    public boolean writeTrustRoots() throws IOException {
        return writeTrustRoots(getTrustRootPath());
    }

    /**
     * Writes the retrieved trust roots to a trusted certificates directory.
     *
     * @param directory path where the trust roots should be written
     * @return true if trust roots are written successfully, false if no
     * trust roots are available to be written
     */
    public boolean writeTrustRoots(String directory) throws IOException {
        if (this.trustrootFilenames == null || this.trustrootData == null) {
            return false;
        }
        File rootDir = new File(directory);
        if (!rootDir.exists()) {
            rootDir.mkdirs();
        }
        for (int i = 0; i < trustrootFilenames.length; i++) {
            FileOutputStream out = new FileOutputStream(directory
                    + File.separator + this.trustrootFilenames[i]);
            out.write(this.trustrootData[i].getBytes());
            out.close();
        }
        return true;
    }

    /**
     * Gets the trusted CA certificates returned by the MyProxy server.
     *
     * @return trusted CA certificates, or null if none available
     */
    public X509Certificate[] getTrustedCAs() throws CertificateException {
        if (trustrootData == null)
            return null;
        return CertUtil.getX509CertsFromStringList(trustrootData, trustrootFilenames);
    }


    /**
     * Gets the CRLs returned by the MyProxy server.
     *
     * @return CRLs or null if none available
     */
    public X509CRL[] getCRLs() throws CertificateException {
        if (trustrootData == null)
            return null;
        CertificateFactory certFactory = CertificateFactory
                .getInstance("X.509");
        Collection<X509CRL> c = new ArrayList<X509CRL>(trustrootData.length);
        for (int i = 0; i < trustrootData.length; i++) {
            String crlData = trustrootData[i];
            int index = crlData.indexOf("-----BEGIN X509 CRL-----");
            if (index >= 0) {
                crlData = crlData.substring(index);
                ByteArrayInputStream inputStream = new ByteArrayInputStream(
                        crlData.getBytes());
                try {
                    X509CRL crl = (X509CRL) certFactory
                            .generateCRL(inputStream);
                    c.add(crl);
                } catch (Exception e) {
                    getMlf().warn(this.trustrootFilenames[i]
                            + " can not be parsed as an X509CRL.");
                }
            }
        }
        if (c.isEmpty())
            return null;
        return c.toArray(new X509CRL[0]);
    }

    /**
     * Returns the trusted certificates directory location where
     * writeTrustRoots() will store certificates.
     */
    public static String getTrustRootPath() {
        String path;

        path = System.getenv("X509_CERT_DIR");
        if (path == null) {
            path = System.getProperty("X509_CERT_DIR");
        }
        if (path == null) {
            path = System.getProperty("user.home") + TRUSTED_CERT_PATH;
        }
        return path;
    }

    /**
     * Gets the existing trusted CA certificates directory.
     *
     * @return directory path string or null if none found
     */
    public static String getExistingTrustRootPath() {
        String path, GL;

        GL = System.getenv("GLOBUS_LOCATION");
        if (GL == null) {
            GL = System.getProperty("GLOBUS_LOCATION");
        }

        path = System.getenv("X509_CERT_DIR");
        if (path == null) {
            path = System.getProperty("X509_CERT_DIR");
        }
        if (path == null) {
            path = getDir(System.getProperty("user.home") + TRUSTED_CERT_PATH);
        }
        if (path == null) {
            path = getDir("/etc/grid-security/certificates");
        }
        if (path == null) {
            path = getDir(GL + File.separator + "share" + File.separator
                    + "certificates");
        }

        return path;
    }

    /**
     * Returns the default Globus proxy file location.
     */
    public static String getProxyLocation() throws IOException {
        String loc, suffix = null;
        Process proc;
        BufferedReader bufferedReader;

        loc = System.getenv("X509_USER_PROXY");
        if (loc == null) {
            loc = System.getProperty("X509_USER_PROXY");
        }
        if (loc != null) {
            return loc;
        }

        try {
            proc = Runtime.getRuntime().exec("id -u");
            bufferedReader = new BufferedReader(new InputStreamReader(proc
                    .getInputStream()));
            suffix = bufferedReader.readLine();
        } catch (IOException e) {
            // will fail on windows
        }

        if (suffix == null) {
            suffix = System.getProperty("user.name");
            if (suffix != null) {
                suffix = suffix.toLowerCase();
            } else {
                suffix = "nousername";
            }
        }

        if (File.separator.equals("/")) { // Unix
            return "/tmp/" + X509_USER_PROXY_FILE + suffix;
        } else {
            return System.getProperty("java.io.tmpdir") + File.separator
                    + X509_USER_PROXY_FILE + suffix;
        }
    }


    /**
     * Provides a simple command-line interface.
     */
    public static void main(String[] args) {
        try {
            Logger logger = Logger.getLogger(MyProxyLogon.class.getName());
            logger.setUseParentHandlers(false);
            MyLoggingFacade facade = new MyLoggingFacade(logger);
            MyProxyLogon m = new MyProxyLogon(facade);

            //MyLoggingFacade myLoggingFacade = new MyLoggingFacade(MyProxyLogon.class.getName());
            //MyProxyLogon m = new MyProxyLogon(myLoggingFacade);
            // Console cons = System.console();
            String passphrase = null;
            X509Certificate[] CAcerts;
            X509CRL[] CRLs;
            //MyProxyLogon.logger.setLevel(Level.ALL);
            // Turn on for debugging if needed.
            // if (cons != null) {
            // char[] pass = cons.readPassword("[%s]", "MyProxy Passphrase:
            // ");
            // if (pass != null) {
            // passphrase = new String(pass);
            // }
            // } else {
            System.out
                    .println("Warning: terminal will echo passphrase as you type.");
            System.out.print("MyProxy Passphrase: ");
            passphrase = m.readLine(System.in);
            // }
            if (passphrase == null) {
                System.err.println("Error reading passphrase.");
                System.exit(1);
            }
            m.setPassphrase(passphrase);
            m.requestTrustRoots(true);
            m.getCredentials();
            m.writeProxyFile();
            System.out.println("Credential written successfully.");
            CAcerts = m.getTrustedCAs();
            if (CAcerts != null) {
                System.out.println(Integer.toString(CAcerts.length)
                        + " CA certificates received.");
            }
            CRLs = m.getCRLs();
            if (CRLs != null) {
                System.out.println(Integer.toString(CRLs.length)
                        + " CRLs received.");
            }
            if (m.writeTrustRoots()) {
                System.out.println("Wrote trust roots to "
                        + MyProxyLogon.getTrustRootPath() + ".");
            } else {
                System.out
                        .println("Received no trust roots from MyProxy server.");
            }
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    private void setFilePermissions(String file, String mode) {
        String command = "chmod " + mode + " " + file;
        try {
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            getMlf().warn("Failed to run: " + command); // windows
        }
    }

    private String readLine(InputStream is) throws IOException {
        StringBuffer sb = new StringBuffer();
        for (int c = is.read(); c > 0 && c != '\n'; c = is.read()) {
            sb.append((char) c);
        }
        if (sb.length() > 0) {
            return new String(sb);
        }
        return null;
    }

    private static String getDir(String path) {
        if (path == null)
            return null;
        File f = new File(path);
        if (f.isDirectory() && f.canRead()) {
            return f.getAbsolutePath();
        }
        return null;
    }


    public boolean isReady(){
        return this.state == State.READY;
    }
    public boolean isConnected(){
        //  Cannot be logged on unless connected, so this should check both.
        return (this.state == State.CONNECTED) || (this.state == State.LOGGEDON);
    }
    public boolean isLoggedOn(){
        return this.state == State.LOGGEDON;
    }
    public boolean isDone(){
        return this.state == State.DONE;
    }
    @Override

    public String toString() {
        return getClass().getSimpleName() + "[host=" + getHost() + ", port=" + getPort() + ", for username=" + getUsername() + "]";
    }

}
