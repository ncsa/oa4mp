package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.ssl.SSLKeystoreConfiguration;

import javax.net.ssl.KeyManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * A very simple facade that will carry out getting certificates using MyProxy Logon. This is
 * intended for server-side use where there is a set configuration for repeated requests. There are
 * two basic modes of operation:
 * <ol>
 * <li>Username and passphrase are supplied on a per request basis</li>
 * <li>A trust relation exists with the MyProxy server and credentials are retrieved by username.</li>
 * </ol>
 * In all cases, a cert request must be supplied and the result will be a certificate chain.
 * In the first case, a username and password must be supplied. In the second, no passphrase
 * is needed (or a <code>null</code> one could be supplied).
 * <p>LOAs, that is to say different levels of assurance are also supported here if they are
 * set in the {@link ServiceFacadeConfiguration}. </p>
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  5:11:24 PM
 */
public class MyProxyServiceFacade {
    protected int getLOAPort(String id) {
        if (id == null || id.length() == 0 || facadeConfiguration.loas == null || facadeConfiguration.loas.isEmpty()) {
            return facadeConfiguration.getPort(); // This is the port for the basic MyProxy server
        }
        Integer x = facadeConfiguration.loas.get(id);
        if (x == null) {
            return facadeConfiguration.getPort();  // If there is no specific port, then default to basic.
        }
        return x;
    }

    /**
     * Constructor for first case, where the username and password is used for each call, so no keystore is required.
     *
     * @param facadeConfiguration
     */
    public MyProxyServiceFacade(ServiceFacadeConfiguration facadeConfiguration) {
        this.facadeConfiguration = facadeConfiguration;
        sslKeystoreConfiguration = new SSLKeystoreConfiguration();
        sslKeystoreConfiguration.setUseDefaultJavaTrustStore(true);

    }

    /**
     * Constructor for second case, where the server will use a host cert to connect to MyProxy.
     *
     * @param facadeConfiguration
     * @param sslKeystoreConfiguration
     */
    public MyProxyServiceFacade(ServiceFacadeConfiguration facadeConfiguration, SSLKeystoreConfiguration sslKeystoreConfiguration) {
        this.facadeConfiguration = facadeConfiguration;
        this.sslKeystoreConfiguration = sslKeystoreConfiguration;
    }


    /**
     * Get the current configuration.
     *
     * @return
     */
    public ServiceFacadeConfiguration getFacadeConfiguration() {
        return facadeConfiguration;
    }


    /**
     * Get the current keystore.
     *
     * @return
     */
    public SSLKeystoreConfiguration getSslKeystoreConfiguration() {
        return sslKeystoreConfiguration;
    }


    public boolean hasSSL() {
        return sslKeystoreConfiguration != null;
    }

    SSLKeystoreConfiguration sslKeystoreConfiguration;

    ServiceFacadeConfiguration facadeConfiguration;

    /**
     * Most basic call. Just the username, password and cert request are required. Note that the lifetime is set to zero
     * as a default.
     *
     * @param userDN
     * @param password
     * @param derCertRequest
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN, String password, int port, byte[] derCertRequest) throws IOException, GeneralSecurityException {
        return getCerts(userDN, password, port, 0, derCertRequest);
    }

    /**
     * This method is to be used when the server logs on to MyProxy using a host cert, so no passphrase is required.
     *
     * @param userDN
     * @param port
     * @param lifetime
     * @param derCertRequest
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN,
                                                             int port,
                                                             long lifetime,
                                                             byte[] derCertRequest) throws IOException, GeneralSecurityException {
        return getCerts(userDN, null, port, lifetime, derCertRequest);
    }

    /**
     * The method that does the work, actually. Every other method simply invokes this one.
     *
     * @param userDN
     * @param password
     * @param port
     * @param lifetime
     * @param derCertRequest
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN,
                                                             String password,
                                                             int port,
                                                             long lifetime,
                                                             byte[] derCertRequest) throws IOException, GeneralSecurityException {
        MyProxyLogon myproxy = new MyProxyLogon();
        myproxy.setUsername(userDN);
        // if not over-ridden, use whatever the default port from the configuration is.
        if (port < 0) {
            myproxy.setPort(getFacadeConfiguration().getPort());
        } else {
            myproxy.setPort(port);
        }
        myproxy.setHost(getFacadeConfiguration().getHostname());
        if (password == null) {
            // If this is being used by a service (vs. as a facade for users) a host cert will be
            // used for the login, therefore, there will be no password.
            // MyProxy must have a non-null password, so just supply an empty one.
            myproxy.setPassphrase("");
        } else {
            myproxy.setPassphrase(password);
        }
        if (lifetime != 0) {
            myproxy.setLifetime((int) (lifetime / 1000)); // convert ms -> seconds.
        }
        myproxy.setKeyManagerFactory(getKeyManagerFactory());
        myproxy.connect();
        myproxy.logon();
        myproxy.getCredentials(derCertRequest);
        myproxy.disconnect();
        if (myproxy.getCertificates() == null || myproxy.getCertificates().isEmpty()) {
            throw new GeneralException("MyProxy did not return a certificate");
        }
        return myproxy.getCertificates();

    }


    /**
     * Call that allows specification of the level of assurance and the lifetime.
     *
     * @param userDN
     * @param password
     * @param loa
     * @param lifetime       Set equal to zero to accept whatever the default is
     * @param derCertRequest
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN,
                                                             String password,
                                                             long lifetime,
                                                             byte[] derCertRequest,
                                                             String loa) throws IOException, GeneralSecurityException {
        int port = 0;
        // Determine the correct Certificate Authority. At this point there are 3 instances of myproxy to choose from...
        port = getLOAPort(loa);
        return getCerts(userDN, password, port, lifetime, derCertRequest);
    }


    /**
     * Get a cert using the username and password as well as the default configured port.
     *
     * @param userDN
     * @param password
     * @param lifetime
     * @param derCertRequest
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     * @deprecated
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN, String password, long lifetime, byte[] derCertRequest) throws IOException, GeneralSecurityException {
        return getCerts(userDN, password, getFacadeConfiguration().getPort(), lifetime, derCertRequest);
    }


    public synchronized Collection<X509Certificate> getCerts(String userDN, String password, byte[] derCertRequest, long lifetime) throws IOException, GeneralSecurityException {
        return getCerts(userDN, password, getFacadeConfiguration().getPort(), lifetime, derCertRequest);
    }

    /**
     * Method to get certs if the server is using a host cert.
     *
     * @param userDN
     * @param derCertRequest
     * @param lifetime
     * @param loa
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN, byte[] derCertRequest, long lifetime, String loa) throws IOException, GeneralSecurityException {
        return getCerts(userDN, null, lifetime, derCertRequest, loa);
    }


    /**
     * Note this was deprecated since having the cert lifetime (a long) as the second argument lead to people misusing it
     * and relying on Java to disambiguate the call. Java would convert the value to an int and then call the very
     * similar method whereby the argument is a port number. Use {@link #getCerts(String, byte[], long, String)}
     *
     * @param userDN
     * @param lifetime
     * @param derCertRequest
     * @param loa
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     * @deprecated
     */
    public synchronized Collection<X509Certificate> getCerts(String userDN, long lifetime, byte[] derCertRequest, String loa) throws IOException, GeneralSecurityException {
        return getCerts(userDN, null, lifetime, derCertRequest, loa);
    }

    /**
     * Gets the key manager associated with the given keystore.
     *
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    protected KeyManagerFactory getKeyManagerFactory() throws IOException, GeneralSecurityException {
        if (keyManagerFactory == null) {
            keyManagerFactory = KeyManagerFactory.getInstance(getSslKeystoreConfiguration().getKeyManagerFactory());
            KeyStore ks = KeyStore.getInstance(getSslKeystoreConfiguration().getKeystoreType());
            FileInputStream fis = new FileInputStream(getSslKeystoreConfiguration().getKeystore());
            ks.load(fis, getSslKeystoreConfiguration().getKeystorePasswordChars());
            keyManagerFactory.init(ks, getSslKeystoreConfiguration().getKeystorePasswordChars());
            // NOTE do NOT close the file input stream. This is consumed at some random point in the
            // future and if is closed will cause a "KeyManagerFactoryImpl is not initialized" exception!
        }
        return keyManagerFactory;
    }

    static KeyManagerFactory keyManagerFactory;

}
