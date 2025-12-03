package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.util.AbstractCLIApprover;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/27/12 at  3:45 PM
 */
public class CLIApprover extends AbstractCLIApprover {
    @Override
    public ConfigurationLoader<? extends ServiceEnvironmentImpl> getLoader() {
        return new OA2CFConfigurationLoader<>(getCfNode());
    }

    public static void main(String[] args) {
        AbstractCLIApprover approver = new CLIApprover();
        try {
            System.out.println("logging to file " + new File(approver.getLogfileName()).getAbsolutePath());
            approver.run(args);
        } catch (Throwable e) {
            // Since this will probably be called only by a bash script, catch all errors and exceptions
            // then return a non-zero exit code
            e.printStackTrace();
            System.exit(1);
        }
    }
}
