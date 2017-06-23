package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ConnectionCacheRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ExceptionEventNotifier;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
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
import edu.uiuc.ncsa.security.util.mail.MailUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairPopulationThread;

import javax.servlet.ServletException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet.ERROR_NOTIFICATION_BODY_KEY;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet.ERROR_NOTIFICATION_SUBJECT_KEY;

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

    String getTemplate(File filename) throws IOException {

        String body = "";
        try {
            FileInputStream fr = new FileInputStream(filename);
            StringBuffer sb = new StringBuffer();
            int z = 0;
            while ((z = fr.read()) != -1) {
                sb.append((char) z);
            }
            body = sb.toString();
            fr.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return body;
    }


    static boolean notifiersSet = false;

    protected NewClientNotifier createNewClientNotifier(MailUtil mailUtil, MyLoggingFacade logger){
        return new NewClientNotifier(mailUtil, logger);
    }

     public void setupNotifiers() throws IOException {
         // do this once or you will have a message sent for each listener!
         if (notifiersSet) return;
         MyProxyDelegationServlet mps = (MyProxyDelegationServlet) getServlet();
         ServiceEnvironmentImpl env = (ServiceEnvironmentImpl) getEnvironment();
         MyLoggingFacade logger = env.getMyLogger();
         // debugging this...
         NewClientNotifier newClientNotifier = createNewClientNotifier(env.getMailUtil(), logger);
         MyProxyDelegationServlet.addNotificationListener(newClientNotifier);
         MailUtil x = new MailUtil(env.getMailUtil().getMailEnvironment());
         String fName = mps.getServletContext().getInitParameter(ERROR_NOTIFICATION_SUBJECT_KEY);
         if (fName == null) {
             logger.info("No error notification subject set. Skipping...");
             notifiersSet = true;
             return;
         } else {
             logger.info("Set error notification subject to " + fName);
         }
         x.setSubjectTemplate(getTemplate(new File(fName)));

         fName = mps.getServletContext().getInitParameter(ERROR_NOTIFICATION_BODY_KEY);
         if (fName == null) {
             logger.info("No error notification message body set. Skipping...");
             notifiersSet = true;
             return;
         } else {
             logger.info("Set error notification message body to " + fName);
         }

         x.setMessageTemplate(getTemplate(new File(fName)));

         ExceptionEventNotifier exceptionNotifier = new ExceptionEventNotifier(x, logger);
         MyProxyDelegationServlet.addNotificationListener(exceptionNotifier);
         notifiersSet = true;
     }

    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        isInitRun = true;

        MyProxyDelegationServlet mps = (MyProxyDelegationServlet) getServlet();
        try {
            //mps.storeUpdates();
            mps.processStoreCheck(mps.getTransactionStore());
            mps.processStoreCheck(mps.getServiceEnvironment().getClientStore());
            mps.processStoreCheck(mps.getServiceEnvironment().getClientApprovalStore());

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
            setupNotifiers();
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
