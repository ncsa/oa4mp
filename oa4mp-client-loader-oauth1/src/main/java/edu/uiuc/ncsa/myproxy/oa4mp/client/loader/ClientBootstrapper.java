package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.servlet.Bootstrapper;
import edu.uiuc.ncsa.security.servlet.Initialization;
import org.apache.commons.configuration.tree.ConfigurationNode;

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
 * @see {@link Bootstrapper} for more details.
 * <p>Created by Jeff Gaynor<br>
 * on 3/23/12 at  8:45 AM
 */
public class ClientBootstrapper extends AbstractClientBootstrapper{

    /**
     * Create the configuration loader from the found node. If you extend the configuration loader
     * you probably only need to override this method to return a new loader.
     *
     * @param node
     * @return
     * @throws edu.uiuc.ncsa.security.core.exceptions.MyConfigurationException
     */
    public ConfigurationLoader getConfigurationLoader(ConfigurationNode node) throws MyConfigurationException {
        return new ClientLoader(node);
    }

    @Override
    public Initialization getInitialization() {
        return new ClientServletInitializer();
    }
}
