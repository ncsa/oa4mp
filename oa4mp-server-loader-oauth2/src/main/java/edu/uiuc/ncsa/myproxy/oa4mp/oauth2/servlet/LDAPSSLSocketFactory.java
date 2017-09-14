package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.util.ssl.MyTrustManager;
import edu.uiuc.ncsa.security.util.ssl.SSLConfiguration;
import edu.uiuc.ncsa.security.util.ssl.SSLConfigurationUtil;
import net.sf.json.JSONObject;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;

import javax.net.SocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/13/17 at  11:02 AM
 */
public class LDAPSSLSocketFactory extends SocketFactory {
    protected static void say(String x) {
        System.err.println(x);
    }

    public LDAPSSLSocketFactory() {
        say("in constructor");
    }

    public static SocketFactory getDefault() {
        say("in getDefault");

        return new LDAPSSLSocketFactory();
    }

    // creates a socket to the address at the given port
    @Override
    public Socket createSocket(InetAddress address, int port) throws IOException {
        say("in create socket #1");
        return null;
    }

    protected SSLContext getContext() throws NoSuchAlgorithmException {
        SSLContext sc = SSLContext.getInstance(getSslConfiguration().getTlsVersion());
        return sc;
    }

    protected SSLSocketFactory getSF() throws GeneralSecurityException, IOException {
        SSLContext sc = SSLContext.getInstance("SSL");
        MyTrustManager mtm = new MyTrustManager(null, getSslConfiguration());
        mtm.setHost(getLdapConfiguration().getServer());
        TrustManager[] trustAllCerts = new TrustManager[]{mtm};
        sc.init(getKeyManagerFactory().getKeyManagers(), trustAllCerts, new java.security.SecureRandom());
        SSLSocketFactory sf = sc.getSocketFactory();
        // this.socket = (SSLSocket) sf.createSocket(this.hostLookup(), this.port);
        return sf;
    }

    protected SSLConnectionSocketFactory getSocketFactory() {
        try {
            SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(getContext());
            return socketFactory;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    protected KeyManagerFactory getKeyManagerFactory() throws IOException, GeneralSecurityException {
        if (keyManagerFactory == null) {
            keyManagerFactory = KeyManagerFactory.getInstance(getSslConfiguration().getKeyManagerFactory());
            KeyStore ks = KeyStore.getInstance(getSslConfiguration().getKeystoreType());
            FileInputStream fis = new FileInputStream(getSslConfiguration().getKeystore());
            ks.load(fis, getSslConfiguration().getKeystorePasswordChars());
            keyManagerFactory.init(ks, getSslConfiguration().getKeystorePasswordChars());
            // NOTE do NOT close the file input stream. This is consumed at some random point in the
            // future and if is closed will cause a "KeyManagerFactoryImpl is not initialized" exception!
        }
        return keyManagerFactory;
    }

    static KeyManagerFactory keyManagerFactory;

    // creates a socket at the address (as a string) to the give port
    @Override
    public Socket createSocket(String address, int port) throws IOException {
        say("in create socket #2");
        try {
            return getSF().createSocket(getLdapConfiguration().getServer(), getLdapConfiguration().getPort());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public Socket createSocket(String address, int port, InetAddress localAddress, int localPort) throws IOException, UnknownHostException {
        say("in create socket #3");

        return null;
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        say("in create socket #4");

        return null;
    }

    public static void clear() {
        sslConfiguration = null;
    }

    public static SSLConfiguration getSslConfiguration() {
        return getLdapConfiguration().getSslConfiguration();
    }


    public static LDAPConfiguration getLdapConfiguration() {
        return ldapConfiguration;
    }

    public static void setLdapConfiguration(LDAPConfiguration ldapConfiguration) {
        LDAPSSLSocketFactory.ldapConfiguration = ldapConfiguration;
    }

    static LDAPConfiguration ldapConfiguration;
    protected static SSLConfiguration sslConfiguration;
    static String ldap = "{\"ldap\": " +
            "{\"authorizationType\": \"simple\"," +
            "\"address\": \"registry-test.cilogon.org\"," +
            "\"port\": 636," +
            "\"principal\": \"uid=oa4mp_user,ou=system,o=NANOGrav,dc=cilogon,dc=org\"," +
            "\"password\": \"b6r6r4PFUGOWOa25WL4q\"," +
            "\"searchBase\": \"ou=people,o=NANOGrav,dc=cilogon,dc=org\"," +
            "\"searchAttributes\": [" +
            "{\"name\": \"CILogonPersonMediaWikiUsername\",\"returnAsList\": false,\"returnName\":\"preferred_username\"}," +
            "{\"name\": \"givenName\",\"returnAsList\": false,\"returnName\": \"given_name\"}," +
            "{\"name\": \"sn\",\"returnAsList\": false,\"returnName\": \"family_name\"}," +
            "{\"name\": \"mail\",\"returnAsList\": false,\"returnName\": \"email\"}]," +
            "\"searchName\": \"username\"}}";

    public static void main(String[] args) {
        try {
            DebugUtil.dbg(LDAPSSLSocketFactory.class, System.getProperty("java.home") + "/lib/security/cacerts");
            DebugUtil.setIsEnabled(true);
          //  System.setProperty("javax.net.debug", "ssl");

            JSONObject json = JSONObject.fromObject(ldap);

            LDAPConfiguration ldapConfiguration = LDAPConfigurationUtil.fromJSON(json);
            setLdapConfiguration(ldapConfiguration);
             ldapConfiguration.setContextName("");
            getSslConfiguration().setTlsVersion(SSLConfigurationUtil.TLS_1_2);
            getSslConfiguration().setUseDefaultJavaTrustStore(false);
            getSslConfiguration().setKeystoreType("JKS");
            getSslConfiguration().setKeystorePassword("changeit");
            getSslConfiguration().setKeystore("/home/ncsa/temp/java-certs/cacerts2");
            getSslConfiguration().setTrustRootType("JKS");
            getSslConfiguration().setTrustRootPassword("changeit");
            getSslConfiguration().setTrustRootPath("/home/ncsa/temp/java-certs/cacerts2");
            LDAPScopeHandler x = new LDAPScopeHandler(ldapConfiguration, null);
            LDAPSSLSocketFactory.setLdapConfiguration(ldapConfiguration);
            x.logon();
            UserInfo userInfo = new UserInfo();
            userInfo.getMap().putAll(x.simpleSearch(x.context, "http://cilogon.org/serverA/users/10376", ldapConfiguration.getSearchAttributes()));
            System.out.println(userInfo);

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

}
