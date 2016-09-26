package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.CopyTool;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:27 PM
 */
public class OA2CopyTool extends CopyTool {
    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
        return new OA2ConfigurationLoader<>(getConfigurationNode(), getMyLogger());
    }

    public static void main(String[] args) {
        OA2CopyTool adminTool = new OA2CopyTool();
        try {
            adminTool.run(args);
        } catch (Throwable e) {
            // Since this will probably be called only by a bash script, catch all errors and exceptions
            // then return a non-zero exit code
            e.printStackTrace();
            System.exit(1);
        }
    }
}
