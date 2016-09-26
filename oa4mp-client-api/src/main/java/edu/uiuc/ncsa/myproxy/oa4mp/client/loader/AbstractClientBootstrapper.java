package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.Bootstrapper;
import edu.uiuc.ncsa.security.servlet.ServletConfigUtil;
import edu.uiuc.ncsa.security.util.configuration.ConfigUtil;

import javax.servlet.ServletContext;
import java.io.File;

/**
 * A class required by Tomcat. This is the entry point for loading the configuration file.
 * One feature of this is that it will search for configurations in various default locations
 * using a default file name of <code>client.xml</code>
 * <ul>
 *     <li>$USER_HOME/client.xml</li>
 *     <li>$USER_HOME/oa4mp/client.xml</li>
 *     <li>$USER_DIR/client.xml</li>
 *     <li>$USER_DIR/client.xml</li>
 *     <li>/var/www/config/client.xml</li>
 *     <li>/var/www/config/oa4mp/client.xml</li>
 * </ul>
 *
 * where <code>$USER_HOME</code> is the home directory for the current user and <code>$USER_DIR</code>
 * is he current invocation directory.
 *
 * If all of these locations as well as the servlet context have been checked for usable configurations
 * and none is found, an error is issued stating there is no usable configuration.
 *
 *
 * @see {@link Bootstrapper} for more details.
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/13 at  11:24 AM
 */
public abstract class AbstractClientBootstrapper extends Bootstrapper {
    protected static final String OA4MP_CONFIG_FILE_KEY = "oa4mp:client.config.file";

    protected static final String OA4MP_CONFIG_NAME_KEY = "oa4mp:client.config.name";

    public static final String DEFAULT_CONFIG_FILE_NAME = "client.xml";

    public static final String[] DEFAULT_CONFIG_LOCATIONS = new String[]{
            System.getProperty("user.home") + File.separator + "oa4mp" + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.home") + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.dir") + File.separator + "oa4mp" + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.dir") + File.separator + DEFAULT_CONFIG_FILE_NAME,
            "/var/www/config/" + DEFAULT_CONFIG_FILE_NAME,
            "/var/www/config/" + "oa4mp/" + DEFAULT_CONFIG_FILE_NAME
    }; // last one is unix specific.

    public  String getOa4mpConfigFileKey() {
        return OA4MP_CONFIG_FILE_KEY;
    }

    public String getOa4mpConfigNameKey() {
        return OA4MP_CONFIG_NAME_KEY;
    }


    public ConfigurationLoader loadFromDefaultLocations(MyLoggingFacade logger, String configName) throws Exception {
        logger.info("Searching for configuration name \"" + (configName == null ? "null" : configName) + "\"");
        for (String fileName : DEFAULT_CONFIG_LOCATIONS) {
            logger.info("Searching for configuration file \"" + fileName + "\"");
            File f = new File(fileName);
            if (f.exists() && f.isFile()) {
                try {
                    logger.info("loading configuration \"" + (configName == null ? "(none)" : configName) + "\" from file " + fileName);
                    return getConfigurationLoader(ConfigUtil.findConfiguration(fileName, configName, ClientXMLTags.COMPONENT));
                } catch (Throwable t) {
                }
                logger.info("  ** configuration not found for \"" + fileName + "\"");
            }
        }
        return null;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ServletContext servletContext) throws Exception {
        MyLoggingFacade logger = new MyLoggingFacade(getClass().getSimpleName());
        logger.info("Starting to load configuration");
        try {
            ConfigurationLoader x = getConfigurationLoader(
                    ServletConfigUtil.findConfigurationNode(servletContext, getOa4mpConfigFileKey(), getOa4mpConfigNameKey(), ClientXMLTags.COMPONENT));
            logger.info("Loaded configuration named " + servletContext.getInitParameter(getOa4mpConfigNameKey()) + " from file " + servletContext.getInitParameter(getOa4mpConfigFileKey()));
            return x;
        } catch (MyConfigurationException ce) {
            logger.info("Did not find a configuration via the servlet context:" + ce.getMessage());
        }

        logger.info("No configuration found in servlet context. Trying default locations");
        // That didn't work, so try to look for it in a few other places.
        String configName = servletContext.getInitParameter(getOa4mpConfigNameKey());
        ConfigurationLoader loader = loadFromDefaultLocations(logger, configName);
        if (loader != null) {
            return loader;
        }

        MyConfigurationException cx = new MyConfigurationException("Error: No configuration found anyplace. OA4MP client startup aborted!");
        logger.error(cx);
        throw cx;
    }



}
