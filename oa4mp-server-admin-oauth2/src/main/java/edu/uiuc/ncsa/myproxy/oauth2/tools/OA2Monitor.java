package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.Monitor;
import edu.uiuc.ncsa.oa4mp.oauth2.client.OA2ClientLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  1:35 PM
 */
public class OA2Monitor extends Monitor {

/*
    @Override
    public void doIt() throws Exception {
        OA2MPService xService = new OA2MPService(getClientEnvironment());
        info("Making initial request to service at " + ((AddressableServer) xService.getEnvironment().getDelegationService().getAtServer()).getAddress());
        Identifier assetID = BasicIdentifier.randomID();
        OA2Asset asset = new OA2Asset(assetID);
        AuthorizationGrant ag = new AuthorizationGrantImpl(assetID.getUri());
        try {
            xService.getAccessToken(asset, ag);
            System.exit(1); // this must fail since there is no previous call to the server and no error uri available in the monitor.
        }catch(GeneralException x){
            getMyLogger().error("Attempted to contact server and got an expected exception", x);
        }
    }
*/


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
