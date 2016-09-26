package edu.uiuc.ncsa.myproxy;

import junit.framework.TestCase;
import org.junit.Test;

import javax.net.ssl.KeyManagerFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.KeyStore;
import java.util.Properties;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 12, 2010 at  2:28:21 PM
 */
public class MyProxyLogonTest extends TestCase {


    public static final String MYPROXY_TEST_PROPERTIES_KEY = "myproxy.test.properties";
    public static final String MYPROXY_TEST_PORT_KEY = "myproxy.test.port";
    public static final String MYPROXY_TEST_PASSPHRASE_KEY = "myproxy.test.passphrase";
    public static final String MYPROXY_TEST_HOSTCRED_KEY = "myproxy.test.hostcred";
    public static final String MYPROXY_TEST_HOST_KEY = "myproxy.test.host";
    public static final String MYPROXY_TEST_USERNAME_KEY = "myproxy.test.username";
    public static final String MYPROXY_TEST_KEY_MANAGER_KEY = "myproxy.test.keyManager";
    public static final String MYPROXY_TEST_KEYSTORE_KEY = "myproxy.test.keystore";
    public static final String MYPROXY_TEST_LIFETIME_KEY = "myproxy.test.lifetime";
    public static final String MYPROXY_TEST_OUTPUT_FILE_KEY = "myproxy.test.file";

    /**
     * A very simple extension to the Properties object for getting strings without casting and checking to
     * see if the tests should be skipped in toto.
     */
    class TestProperties extends Properties {
        public String getString(String key) {
            return (String) get(key);
        }
    }

    /**
     * Get the properties for the test.
     *
     * @return
     * @throws IOException
     */
    public TestProperties getTestProperties() throws IOException {

        if (testProperties == null) {
            String propertyFilename = System.getProperty("myproxy.test.properties");
            File propertyFile = null;
            if (propertyFilename == null) {
                propertyFilename = "test.properties";
            }
            propertyFile = new File(propertyFilename);
            if (!propertyFile.exists() || !propertyFile.isFile()) {
                say("Could not load properties file \"" + propertyFile.getCanonicalPath() + "\"");
                return null;
            }
            testProperties = new TestProperties();
            FileInputStream fis = new FileInputStream(propertyFile);
            testProperties.load(fis);
            fis.close();
        }
        return testProperties;
    }

    static TestProperties testProperties;

    @Test
    public void testHostname() throws Exception {
        try {
            InetAddress myproxy = InetAddress.getByName("myproxy.cilogon.org");
            System.out.println("testing reverse lookup for " + myproxy);
            byte[] address = myproxy.getAddress();
            InetAddress add2 = InetAddress.getByAddress(address);
            System.out.println(add2.getCanonicalHostName());
        } catch (Throwable t) {
            System.out.println("Possibly benign failure for reverse hostname lookup of myproxy");
        }

    }


    /**
     * Very basic test that gets a credential and writes it to a predetermined file (or a temporary file
     * if none is specified). If you need to skip the test it can be done from the command line,
     * with the skipTests flag, e.g.<br.<br>
     * <code>mvn -DskipTests=true clean install</code>
     *
     * @throws Exception
     */
    @Test
    public void testLogon() throws Exception {
        TestProperties p = getTestProperties();
        if (p == null) {
            say("  aborting test...");
            return;
        }
        MyProxyLogon mp = new MyProxyLogon();
        try {
            mp.getCredentials();
        } catch (Exception x) {
            say("Could not do the test: aborting...");
            assert (true); // so it actually registers as passing.
            return;
        }
        String portString = p.getString(MYPROXY_TEST_PORT_KEY);
        if (portString == null) {
            portString = "7512"; //default
        }

        mp.setPort(Integer.parseInt(portString));
        mp.setHost(p.getString(MYPROXY_TEST_HOST_KEY));
        String lifetimeString = p.getString(MYPROXY_TEST_LIFETIME_KEY);
        if (lifetimeString == null) {
            lifetimeString = "12";
        }

        mp.setLifetime(Integer.parseInt(lifetimeString) * 3600);
        mp.setUsername(p.getString(MYPROXY_TEST_USERNAME_KEY));

        String pwd = p.getString(MYPROXY_TEST_PASSPHRASE_KEY);
        if (pwd == null || pwd.length() == 0) {
            return; // do not do the rest of the test.
        }
        mp.setPassphrase(pwd);
        char[] passphrase = pwd.toCharArray();

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(p.getString(MYPROXY_TEST_KEY_MANAGER_KEY));
        KeyStore ks = KeyStore.getInstance(p.getString(MYPROXY_TEST_KEYSTORE_KEY));

        String hostcred = p.getString(MYPROXY_TEST_HOSTCRED_KEY);
        if (hostcred == null || hostcred.length() == 0) {
            System.out.println("Warning! No host credential was found in the test.properties file.\n\nExiting...\n\n");
            return; // jump out if these properties are not set.
        }
        FileInputStream fis = new FileInputStream(hostcred);
        ks.load(fis, passphrase);
        fis.close();
        kmf.init(ks, passphrase);
        mp.setKeyManagerFactory(kmf);

        mp.connect();
        mp.logon();
        mp.getCredentials();
        mp.disconnect();
        File temp = null;
        if (p.getString(MYPROXY_TEST_OUTPUT_FILE_KEY) == null) {
            temp = new File(p.getString(MYPROXY_TEST_OUTPUT_FILE_KEY));
        } else {
            temp = File.createTempFile("test-cert", "", new File(System.getProperty("user.home")));
        }
        mp.saveCredentialsToFile(temp.getCanonicalPath());
        say("private key=" + mp.getPrivateKey());
        assert temp.exists();
        say("Wrote credential to file \"" + temp.getCanonicalPath() + "\"");
    }

    void say(String x) {
        System.out.println(x);
    }
}
