package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import org.oa4mp.client.loader.XMLClientLoader;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

/**
 * Wraps what used to be method in {@link edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl}
 * that needed to be generalized.
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/23 at  10:51 AM
 */
public class ConfigLoaderTool {
    public  ConfigurationLoader<? extends AbstractEnvironment> figureOutClientLoader(String fileName, String configName, String componentName) throws Throwable {
        if (fileName.endsWith(".xml")) {
            CFNode node = CFXMLConfigurations.findConfiguration(fileName, componentName, configName);
            XMLClientLoader xmlClientLoader = new XMLClientLoader(node);
            return xmlClientLoader;
        }
        return null;
    }
    public  ConfigurationLoader<? extends AbstractEnvironment> figureOutServerLoader(String fileName, String configName, String componentName) throws Throwable {
        if (fileName.endsWith(".xml")) {
            CFNode node = CFXMLConfigurations.findConfiguration(fileName, componentName, configName);
            OA2CFConfigurationLoader serverLoader = new OA2CFConfigurationLoader<>(node);
            return serverLoader;
        }
        return null;
    }
}
