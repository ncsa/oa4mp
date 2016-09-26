package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ConnectionCacheRetentionPolicy;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cache;
import edu.uiuc.ncsa.security.core.cache.CachedObject;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.ValidTimestampPolicy;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.Initialization;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairPopulationThread;

import javax.servlet.ServletException;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  10:37 AM
 */
public class OA4MPServletInitializer implements Initialization {
    protected ExceptionHandler exceptionHandler;

    @Override
    public ExceptionHandler getExceptionHandler() {
        if (exceptionHandler == null) {
            exceptionHandler = new OA4MPExceptionHandler(getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

    protected static boolean isInitRun = false;


    AbstractEnvironment environment;

    @Override
    public AbstractEnvironment getEnvironment() {
        return environment;
    }


    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        isInitRun = true;
        MyProxyDelegationServlet mps = (MyProxyDelegationServlet) getServlet();
        try {
            mps.storeUpdates();
        } catch (IOException | SQLException e) {
            e.printStackTrace();
            throw new ServletException("Could not update table", e);
        }
        Cleanup transactionCleanup = MyProxyDelegationServlet.transactionCleanup;
        ServiceEnvironmentImpl env = (ServiceEnvironmentImpl) getEnvironment();

        MyLoggingFacade logger = env.getMyLogger();
        logger.info("Cleaning up incomplete client registrations");

        if (transactionCleanup == null) {
            transactionCleanup = new Cleanup<>(logger);
            MyProxyDelegationServlet.transactionCleanup = transactionCleanup; // set it in the servlet
            transactionCleanup.setStopThread(false);
            transactionCleanup.setMap(env.getTransactionStore());
            transactionCleanup.addRetentionPolicy(new ValidTimestampPolicy());
            transactionCleanup.start();
            logger.info("Starting transaction store cleanup thread");
        }
        Cleanup<Identifier, CachedObject> myproxyConnectionCleanup = MyProxyDelegationServlet.myproxyConnectionCleanup;
        if (myproxyConnectionCleanup == null) {
            myproxyConnectionCleanup = new Cleanup<Identifier, CachedObject>(logger) {
                @Override
                public List<CachedObject> age() {
                    List<CachedObject> x = super.age();
                    // by this point is has been removed from the cache. Rest of this
                    // is just trying to clean up afterwards.
                    for (CachedObject co : x) {
                        Object mp = co.getValue();
                        if (mp instanceof MyProxyConnectable) {
                            try {
                                ((MyProxyConnectable) mp).close();
                            } catch (Throwable t) {
                                // don't care if it fails, get rid of it.
                            }
                        }

                    }
                    return x;
                }
            };
            MyProxyDelegationServlet.myproxyConnectionCleanup = myproxyConnectionCleanup; // set it in the servlet
            myproxyConnectionCleanup.setStopThread(false);
            Cache myproxyConnectionCache = MyProxyDelegationServlet.myproxyConnectionCache;
            if (myproxyConnectionCache == null) {
                myproxyConnectionCache = new Cache();
                MyProxyDelegationServlet.myproxyConnectionCache = myproxyConnectionCache; // set it in the servlet
            }
            myproxyConnectionCleanup.setMap(myproxyConnectionCache);
            myproxyConnectionCleanup.addRetentionPolicy(new ConnectionCacheRetentionPolicy(myproxyConnectionCache, env.getTransactionStore()));
            myproxyConnectionCleanup.start();
            logger.info("Starting myproxy connection cache cleanup thread");
        }
        AbstractCLIApprover.ClientApprovalThread caThread = MyProxyDelegationServlet.caThread;
        if (caThread != null && !caThread.isAlive()) {
            caThread.setStopThread(false);
            caThread.start();
        }
        KeyPairPopulationThread kpt = MyProxyDelegationServlet.kpt;
        if (kpt != null && !kpt.isAlive()) {
            kpt.setStopThread(false);
            kpt.start();
        }
        try {
            mps.setupNotifiers();
        } catch (IOException e) {
            throw new GeneralException("Error: could not set up notifiers ", e);
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
