package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.loader.ClientServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.oa4mp.oauth2.client.servlet.OA2ClientExceptionHandler;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;

import javax.servlet.ServletException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  12:31 PM
 */
public class OA2ClientServletInitializer extends ClientServletInitializer {
    @Override
    public ExceptionHandler getExceptionHandler() {
        if(exceptionHandler == null){
            exceptionHandler = new OA2ClientExceptionHandler((ClientServlet) getServlet(), getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

    @Override
    public void init() throws ServletException {
        if(hasRun) return;
        super.init();
        OA2ClientEnvironment ce = (OA2ClientEnvironment) getEnvironment();
        if (ce.isEnableAssetCleanup()) {
            ClientServlet.assetCleanup.getRetentionPolicies().clear();
            ClientServlet.assetCleanup.addRetentionPolicy(new AssetRetentionPolicy(ce.getAssetStore()));
            ce.getMyLogger().info("Finished setting up asset store retention policies");
        }
    }
}
