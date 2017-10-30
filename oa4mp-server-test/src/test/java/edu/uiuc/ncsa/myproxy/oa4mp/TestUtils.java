package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;
import java.net.URL;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.COMPONENT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/4/12 at  2:46 PM
 */
public class TestUtils {
    // gets set in the test suite class initialize method!
    public static AbstractBootstrapper getBootstrapper() {
        return bootstrapper;
    }

    public static void setBootstrapper(AbstractBootstrapper bootstrapper) {
        TestUtils.bootstrapper = bootstrapper;
    }

    static AbstractBootstrapper bootstrapper;
    public static void setMemoryStoreProvider(TestStoreProvider memoryStoreProvider) {
        TestUtils.memoryStoreProvider = memoryStoreProvider;
    }

    private static TestStoreProvider memoryStoreProvider;
    private static TestStoreProvider fsStoreProvider;
    private static TestStoreProvider pgStoreProvider;
    private static TestStoreProvider mySQLStoreProvider;
    private static TestStoreProvider h2StoreProvider;
    private static TestStoreProvider derbyStoreProvider;
    private static TestStoreProvider agStoreProvider;

    public static TestStoreProvider getAgStoreProvider() {
        return agStoreProvider;
    }

    public static void setAgStoreProvider(TestStoreProvider ags) {
        agStoreProvider = ags;
    }

    public static TestStoreProvider getMemoryStoreProvider() {
        return memoryStoreProvider;
    }

    public static TestStoreProvider getFsStoreProvider() {
        return fsStoreProvider;
    }

    public static void setFsStoreProvider(TestStoreProvider fsStoreProvider) {
        TestUtils.fsStoreProvider = fsStoreProvider;
    }

    public static TestStoreProvider getMySQLStoreProvider() {
        return mySQLStoreProvider;
    }

    public static void setMySQLStoreProvider(TestStoreProvider mySQLStoreProvider) {
        TestUtils.mySQLStoreProvider = mySQLStoreProvider;
    }

    public static TestStoreProvider getPgStoreProvider() {
        return pgStoreProvider;
    }

    public static void setPgStoreProvider(TestStoreProvider pgStoreProvider) {
        TestUtils.pgStoreProvider = pgStoreProvider;
    }

    public static TestStoreProvider getDerbyStoreProvider() {
        return derbyStoreProvider;
    }

    public static void setDerbyStoreProvider(TestStoreProvider derbyStoreProvider) {
        TestUtils.derbyStoreProvider = derbyStoreProvider;
    }

    /**
     * Loads a given configuration from a specified (on the command line) file.
     * Generally you should stick all of your configurations for a test run in a single
     * file then use this to pull off the ones you need, by name. If you do not specify a name
     * this will try to get a configuration with the name specified at the command line.
     *
     * @param configName
     * @return
     */
    public static ConfigurationNode findConfigNode(String configName) {
        try {
            String fileName = System.getProperty( getBootstrapper().getOa4mpConfigFileKey());
            if (fileName == null) {
                throw new MyConfigurationException("Error: No configuration file specified");
            }
            XMLConfiguration cfg = null;
            if (fileName.length() != 0) {
                // A properties file is supplied. Use that.
                try {
                    cfg = Configurations.getConfiguration(new File(fileName));
                } catch (MyConfigurationException cx) {
                    cx.printStackTrace();
                    // plan B, maybe it's in the deployment itself? try to get as a resource
                    URL url = TestUtils.class.getResource(fileName);
                    if (url == null) {
                        throw new MyConfigurationException("Error:No configuration found. for \"" + fileName + "\"");
                    }
                    cfg = Configurations.getConfiguration(url);

                }
            } else {
                throw new MyConfigurationException("Error:No configuration file found.");

            }
            ConfigurationNode cn = null;

            if (configName == null) {
                // try to find a specified configuration.
                String cfgName = System.getProperty(getBootstrapper().getOa4mpConfigNameKey());
                if (cfgName == null) {
                    System.out.println("no name for a configuration given");
                    cn = cfg.configurationAt(COMPONENT).getRootNode();

                } else {
                    System.out.println("getting named configuration \"" + cfgName + "\"");
                    cn = Configurations.getConfig(cfg, COMPONENT, cfgName);
                }

            } else {
                cn = Configurations.getConfig(cfg, COMPONENT, configName);
            }
            return cn;
        } catch (Exception x) {
            throw new MyConfigurationException("Error loading configuration", x);
        }
    }

    public static void setH2StoreProvider(TestStoreProvider h2) {
        h2StoreProvider = h2;
    }
}
