package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags;
import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Bootstrapper;
import edu.uiuc.ncsa.security.servlet.ServletConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import javax.servlet.ServletContext;
import java.util.Enumeration;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/21/12 at  11:09 AM
 */
public abstract class AbstractBootstrapper extends Bootstrapper {
    private static String OA4MP_CONFIG_FILE_KEY = "oa4mp:server.config.file";
    private static String OA4MP_CONFIG_NAME_KEY = "oa4mp:server.config.name";

    public String getOa4mpConfigFileKey() {
        return OA4MP_CONFIG_FILE_KEY;
    }

    public String getOa4mpConfigNameKey() {
        return OA4MP_CONFIG_NAME_KEY;
    }

    protected ConfigurationNode getNode(ServletContext servletContext) throws Exception {
        return ServletConfigUtil.findConfigurationNode(servletContext, getOa4mpConfigFileKey(), getOa4mpConfigNameKey(), OA4MPConfigTags.COMPONENT);
    }


    @Override
    public ConfigurationLoader getConfigurationLoader(ServletContext servletContext) throws Exception {
        if (servletContext.getInitParameter(getOa4mpConfigFileKey()) == null) {
            // If this fails, make a report. There is no debugging or other such things available
            // at this point since no configuration could be loaded. Help track down what happened.
            StringBuilder initParams = new StringBuilder();
            Enumeration e = servletContext.getInitParameterNames();
            boolean isFirst = true;
            while (e.hasMoreElements()) {
                initParams.append((isFirst ? "" : ", ") + e.nextElement());
                if (isFirst) {
                    isFirst = false;
                }
            }
            e = servletContext.getAttributeNames();
            StringBuilder attribs = new StringBuilder();
            isFirst = false;
            while (e.hasMoreElements()) {
                attribs.append((isFirst ? "" : ", ") + e.nextElement());
                if (isFirst) {
                    isFirst = false;
                }
            }

            throw new MyConfigurationException("Error: No configuration found for file '" + getOa4mpConfigFileKey()
                    + "'. Cannot configure the server. Init parameters are: " + initParams + ", attributes are " + attribs);
        }
        return getConfigurationLoader(getNode(servletContext));
    }

}
