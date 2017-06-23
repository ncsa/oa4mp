package edu.uiuc.ncsa.myproxy.oa4mp.client.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.client.servlet.ClientServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.ValidTimestampPolicy;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.Initialization;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;

import javax.servlet.ServletException;
import java.sql.SQLException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  11:21 AM
 */
public class ClientServletInitializer implements Initialization {
    protected ExceptionHandler exceptionHandler;

    @Override
    public ExceptionHandler getExceptionHandler() {
        if ((exceptionHandler == null)) {
            exceptionHandler = new ClientExceptionHandler((ClientServlet) getServlet(), getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

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
        ClientEnvironment ce = (ClientEnvironment) getEnvironment();
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
                assetCleanup = new Cleanup<Identifier, Asset>(logger);
                assetCleanup.setStopThread(false);
                assetCleanup.setMap(ce.getAssetStore());
                assetCleanup.addRetentionPolicy(new ValidTimestampPolicy(ce.getMaxAssetLifetime()));
                logger.info("Starting asset cleanup thread");
                assetCleanup.start();
                ClientServlet.assetCleanup = assetCleanup;
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
}
