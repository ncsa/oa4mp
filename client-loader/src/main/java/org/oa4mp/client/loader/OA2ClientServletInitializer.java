package org.oa4mp.client.loader;

import org.oa4mp.client.api.Asset;
import org.oa4mp.client.api.servlet.ClientServlet;
import org.oa4mp.client.loader.servlet.OA2ClientExceptionHandler;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.cache.ValidTimestampPolicy;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.Initialization;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;

import javax.servlet.ServletException;
import java.sql.SQLException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  12:31 PM
 */
public class OA2ClientServletInitializer implements Initialization/*extends ClientServletInitializer*/ {
    protected ExceptionHandler exceptionHandler;


    protected boolean hasRun = false;
    AbstractEnvironment environment;

    @Override
    public AbstractEnvironment getEnvironment() {
        return environment;
    }

    @Override
    public void init() throws ServletException {
        if (hasRun) return;
        hasRun = true; // run it once and only once.
        MyLoggingFacade logger = getEnvironment().getMyLogger();
        OA2ClientEnvironment ce = (OA2ClientEnvironment) getEnvironment();
        DebugUtil.setInstance(ce.getMetaDebugUtil());
        // This next bit is a
        if (ce.hasAssetStore()) {
            if (ce.getAssetStore() instanceof SQLStore) {
                SQLStore sqlStore = (SQLStore) ce.getAssetStore();
                try {
                    sqlStore.checkTable();
                    sqlStore.checkColumns();
                } catch (SQLException sqlX) {
                    logger.warn("Could not update store table:" + sqlX.getMessage());
                }
            }
            Cleanup<Identifier, Asset> assetCleanup = ClientServlet.assetCleanup;
            if (ce.isEnableAssetCleanup() && assetCleanup == null) {
                //assetCleanup = new Cleanup<Identifier, Asset>(logger, "asset cleanup");
                LockingCleanup ac = new LockingCleanup<Identifier, Asset>(logger, "asset cleanup");
                ac.setStopThread(false);
                ac.setStore(ce.getAssetStore());
                ac.addRetentionPolicy(new ValidTimestampPolicy(ce.getMaxAssetLifetime()));
                logger.info("Starting asset cleanup thread");
                assetCleanup = ac;
                assetCleanup.start();
                ClientServlet.assetCleanup = assetCleanup;
            }
            if (ce.isEnableAssetCleanup()) {
                ClientServlet.assetCleanup.getRetentionPolicies().clear();
                ClientServlet.assetCleanup.addRetentionPolicy(new AssetRetentionPolicy(ce.getAssetStore()));
                ce.getMyLogger().info("Finished setting up asset store retention policies");
            }
        } else {
            logger.info("No assets store, so no cleanup possible.");
        }
    }

    @Override
    public void setEnvironment(AbstractEnvironment environment) {
        this.environment = environment;
    }

    AbstractServlet servlet;

    @Override
    public AbstractServlet getServlet() {
        return servlet;
    }

    @Override
    public void setServlet(AbstractServlet servlet) {
        this.servlet = servlet;
    }
    @Override
    public ExceptionHandler getExceptionHandler() {
        if(exceptionHandler == null){
            exceptionHandler = new OA2ClientExceptionHandler((ClientServlet) getServlet(), getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

}
