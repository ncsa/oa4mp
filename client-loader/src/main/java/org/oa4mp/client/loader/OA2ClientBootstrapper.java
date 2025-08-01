package org.oa4mp.client.loader;

import org.oa4mp.client.api.ClientXMLTags;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.Bootstrapper;
import edu.uiuc.ncsa.security.servlet.Initialization;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletXMLConfigUtil;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.servlet.ServletContext;
import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/5/13 at  2:40 PM
 */
public class OA2ClientBootstrapper extends Bootstrapper {
    public static final String OA2_CLIENT_CONFIG_FILE_KEY= "oa4mp:oauth2.client.config.file";
    public static final String OA2_CLIENT_CONFIG_NAME_KEY= "oa4mp:oauth2.client.config.name";
    public static final String DEFAULT_CONFIG_FILE_NAME = "client.xml";

    public String getOa4mpConfigFileKey() {
        return OA2_CLIENT_CONFIG_FILE_KEY;
    }

    public String getOa4mpConfigNameKey() {
        return OA2_CLIENT_CONFIG_NAME_KEY;
    }

    @Override
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new OA2ClientLoader(node);
    }

    @Override
    public Initialization getInitialization() {
        return new OA2ClientServletInitializer();
    }

    public ConfigurationLoader loadFromDefaultLocations(MyLoggingFacade logger, String configName) throws Exception {
        logger.info("Searching for configuration name \"" + (configName == null ? "null" : configName) + "\"");
        for (String fileName : DEFAULT_CONFIG_LOCATIONS) {
            logger.info("Searching for configuration file \"" + fileName + "\"");
            File f = new File(fileName);
            if (f.exists() && f.isFile()) {
                try {
                    logger.info("loading configuration \"" + (configName == null ? "(none)" : configName) + "\" from file " + fileName);
                    ConfigurationNode node = XMLConfigUtil.findMultiNode(fileName, configName, ClientXMLTags.COMPONENT);
                    // old single inheritance
                    //ConfigurationNode node = ConfigUtil.findConfiguration(fileName, configName, ClientXMLTags.COMPONENT);

                    return getConfigurationLoader(node);
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
        String cfgName=servletContext.getInitParameter(getOa4mpConfigNameKey());
        String fileName= servletContext.getInitParameter(getOa4mpConfigFileKey());
        ServletDebugUtil.trace(this, "Attempting to load configuration \"" + cfgName + "\" from file \"" + fileName + "\"");
        logger.info("Starting to load configuration");
        try {
            ConfigurationLoader x = getConfigurationLoader(
                    ServletXMLConfigUtil.findConfigurationNode(servletContext, getOa4mpConfigFileKey(), getOa4mpConfigNameKey(), ClientXMLTags.COMPONENT));
            logger.info("Loaded configuration named " + cfgName + " from file " + fileName);
            return x;
        } catch (MyConfigurationException ce) {
            ServletDebugUtil.trace(this, "Did not find a configuration via the servlet context.");

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
        ServletDebugUtil.error(this, "Failed to find any configuration.", cx);
        logger.error(cx);
        throw cx;
    }

    public static final String[] DEFAULT_CONFIG_LOCATIONS = new String[]{
            System.getProperty("user.home") + File.separator + "oa4mp" + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.home") + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.dir") + File.separator + "oa4mp" + File.separator + DEFAULT_CONFIG_FILE_NAME,
            System.getProperty("user.dir") + File.separator + DEFAULT_CONFIG_FILE_NAME,
            "/var/www/config/" + DEFAULT_CONFIG_FILE_NAME,
            "/var/www/config/" + "oa4mp/" + DEFAULT_CONFIG_FILE_NAME
    }; // last one is unix specific.
}
