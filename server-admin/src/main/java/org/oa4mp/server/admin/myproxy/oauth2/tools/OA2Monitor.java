package org.oa4mp.server.admin.myproxy.oauth2.tools;

import org.oa4mp.server.admin.myproxy.oauth2.base.Monitor;
import org.oa4mp.client.loader.OA2ClientLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:35 PM
 */
public class OA2Monitor extends Monitor {



    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA2ClientLoader(getConfigurationNode());
    }

    public static void main(String[] args) {
        Monitor monitor = new OA2Monitor();
        try {
            monitor.run(args);
        } catch (Throwable e) {
            // Since this will probably be called only by a bash script, catch all errors and exceptions
            // then return a non-zero exit code
            if (monitor.isVerbose()) {
                e.printStackTrace();
            }
            monitor.getMyLogger().error("Error contacting server", e);
            monitor.sendNotification(e);
            System.exit(1);
        }
    }
}
