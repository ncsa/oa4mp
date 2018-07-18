package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
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

    public static void setMemoryStoreProvider(TestStoreProviderInterface memoryStoreProvider) {
        TestUtils.memoryStoreProvider = memoryStoreProvider;
    }

    private static TestStoreProviderInterface memoryStoreProvider;
    private static TestStoreProviderInterface fsStoreProvider;
    private static TestStoreProviderInterface pgStoreProvider;
    private static TestStoreProviderInterface mySQLStoreProvider;
    private static TestStoreProviderInterface h2StoreProvider;
    private static TestStoreProviderInterface derbyStoreProvider;
    private static TestStoreProviderInterface agStoreProvider;

    public static TestStoreProviderInterface getAgStoreProvider() {
        return agStoreProvider;
    }

    public static void setAgStoreProvider(TestStoreProviderInterface ags) {
        agStoreProvider = ags;
    }

    public static TestStoreProviderInterface getMemoryStoreProvider() {
        return memoryStoreProvider;
    }

    public static TestStoreProviderInterface getFsStoreProvider() {
        return fsStoreProvider;
    }

    public static void setFsStoreProvider(TestStoreProviderInterface fsStoreProvider) {
        TestUtils.fsStoreProvider = fsStoreProvider;
    }

    public static TestStoreProviderInterface getMySQLStoreProvider() {
        return mySQLStoreProvider;
    }

    public static void setMySQLStoreProvider(TestStoreProviderInterface mySQLStoreProvider) {
        TestUtils.mySQLStoreProvider = mySQLStoreProvider;
    }

    public static TestStoreProviderInterface getPgStoreProvider() {
        return pgStoreProvider;
    }

    public static void setPgStoreProvider(TestStoreProviderInterface pgStoreProvider) {
        TestUtils.pgStoreProvider = pgStoreProvider;
    }

    public static TestStoreProviderInterface getDerbyStoreProvider() {
        return derbyStoreProvider;
    }

    public static void setDerbyStoreProvider(TestStoreProviderInterface derbyStoreProvider) {
        TestUtils.derbyStoreProvider = derbyStoreProvider;
    }

    /**
     * This returns the key that is used for locating the config file. Override this as needed.
     *
     * @return
     */
    public static String getConfigFileKey() {
        if (getBootstrapper() == null) {
            throw new NullPointerException("Error: you have not set the bootstrapper for this TestUtil class");
        }
        return getBootstrapper().getOa4mpConfigFileKey();
    }
    public static ConfigurationNode findConfigNode(String configName) {
                 return     findConfigNode(null, configName);
    }


    /**
     * Loads a given configuration from a specified (on the command line) file.
     * If you give a file name for the configuration file, it will use that. Otherwise it
     * will look for the key that is used in configuration files and assume that has been
     * passed in as a system property. <br/>
     * Generally you should stick all of your configurations for a test run in a single
     * file then use this to pull off the ones you need, by name. If you do not specify a name
     * this will try to get a configuration with the name specified at the command line.
     *
     * @param configName
     * @return
     */
    public static ConfigurationNode findConfigNode(String fileName, String configName) {
        if (fileName == null) {
            fileName = System.getProperty(getConfigFileKey());
        }
        if (fileName == null) {
            throw new MyConfigurationException("Error: No configuration file specified. Did you set the system property correctly?");
        }
        try {

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
                    DebugUtil.dbg(TestUtils.class, "no name for a configuration given");
                    cn = cfg.configurationAt(COMPONENT).getRootNode();

                } else {
                    DebugUtil.dbg(TestUtils.class, "getting named configuration \"" + cfgName + "\"");
                    cn = Configurations.getConfig(cfg, COMPONENT, cfgName);
                }

            } else {
                cn = Configurations.getConfig(cfg, COMPONENT, configName);
            }
            return cn;
        } catch (Exception x) {
            MyConfigurationException ex = new MyConfigurationException("Error loading configuration with " +
                    "name \"" + configName + "\" from file \"" + fileName + "\".", x);
            DebugUtil.dbg(TestUtils.class, ex.getMessage(), ex);
            throw ex;
        }
    }

    public static void setH2StoreProvider(TestStoreProviderInterface h2) {
        h2StoreProvider = h2;
    }
}
