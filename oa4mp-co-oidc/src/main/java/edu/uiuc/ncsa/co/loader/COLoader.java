package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/17/16 at  10:40 AM
 */
public class COLoader extends OA2ConfigurationLoader {
    public COLoader(ConfigurationNode node) {
        super(node);
    }

    public COLoader(ConfigurationNode node, MyLoggingFacade logger) {
        super(node, logger);
    }

}
