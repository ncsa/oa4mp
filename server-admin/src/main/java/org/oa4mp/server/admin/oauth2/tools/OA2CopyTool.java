package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import org.oa4mp.server.admin.oauth2.base.CopyTool;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:27 PM
 */
public class OA2CopyTool extends CopyTool {
    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
        return new OA2CFConfigurationLoader<>(getCfNode(), getMyLogger());
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
