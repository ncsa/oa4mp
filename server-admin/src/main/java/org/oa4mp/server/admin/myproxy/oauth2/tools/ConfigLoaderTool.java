package org.oa4mp.server.admin.myproxy.oauth2.tools;

import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.client.loader.XMLClientLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * Wraps what used to be method in {@link edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl}
 * that needed to be generalized.
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/23 at  10:51 AM
 */
public class ConfigLoaderTool {
    public  ConfigurationLoader<? extends AbstractEnvironment> figureOutClientLoader(String fileName, String configName, String componentName) throws Throwable {
        if (fileName.endsWith(".xml")) {
            ConfigurationNode node = XMLConfigUtil.findConfiguration(fileName, configName, componentName);
            XMLClientLoader xmlClientLoader = new XMLClientLoader(node);
            return xmlClientLoader;
        }
        return null;
    }
    public  ConfigurationLoader<? extends AbstractEnvironment> figureOutServerLoader(String fileName, String configName, String componentName) throws Throwable {
        if (fileName.endsWith(".xml")) {
            ConfigurationNode node = XMLConfigUtil.findConfiguration(fileName, configName, componentName);
            OA2ConfigurationLoader serverLoader = new OA2ConfigurationLoader<>(node);
            return serverLoader;
        }
        return null;
    }
}
