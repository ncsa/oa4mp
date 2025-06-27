package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.cache.ValidTimestampPolicy;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.servlet.Initialization;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.mail.MailUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairPopulationThread;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.util.AbstractCLIApprover;
import org.oa4mp.server.api.util.NewClientNotifier;

import javax.servlet.ServletException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;

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

    protected NewClientNotifier createNewClientNotifier(MailUtil mailUtil, MyLoggingFacade logger) {
        return new NewClientNotifier(mailUtil, logger);
    }

    public void setupNotifiers() throws IOException {
        // do this once or you will have a message sent for each listener!
        if (notifiersSet) return;
        OA4MPServlet mps = (OA4MPServlet) getServlet();
        ServiceEnvironmentImpl env = (ServiceEnvironmentImpl) getEnvironment();
        MyLoggingFacade logger = env.getMyLogger();
        NewClientNotifier newClientNotifier = createNewClientNotifier(env.getMailUtil(), logger);
        OA4MPServlet.addNotificationListener(newClientNotifier);

        String fName = mps.getServletContext().getInitParameter(EnvServlet.ERROR_NOTIFICATION_SUBJECT_KEY);
        if (fName == null) {
            logger.info("No error notification subject set. Skipping...");
            notifiersSet = true;
            return;
        } else {
            logger.info("Set error notification subject to " + fName);
        }
        MailUtil x = new MailUtil(env.getMailUtil().getMailEnvironment());
        if (x.isEnabled()) {
            // don't set stuff up unless this is enabled.
            x.setSubjectTemplate(getTemplate(new File(fName)));
            x.setMessageTemplate(getTemplate(new File(fName)));
        }
        fName = mps.getServletContext().getInitParameter(EnvServlet.ERROR_NOTIFICATION_BODY_KEY);
        if (fName == null) {
            logger.info("No error notification message body set. Skipping...");
            notifiersSet = true;
            return;
        } else {
            logger.info("Set error notification message body to " + fName);
        }


    /*  Fixes CIL-1852 Notifications on random failures is just too much traffic.
        ExceptionEventNotifier exceptionNotifier = new ExceptionEventNotifier(x, logger);
        MyProxyDelegationServlet.addNotificationListener(exceptionNotifier);*/
        notifiersSet = true;
    }



    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        isInitRun = true;

        OA4MPServlet mps = (OA4MPServlet) getServlet();
        // Partial solution to CIL-355. This at least sets the host for the debug utilities
        // Full solution requires a good deal most tweaking of the logging including
        // determining if log4j is in use and configuring that.
        URI serviceAddress = mps.getServiceEnvironment().getServiceAddress();
        if (serviceAddress != null) {
            DebugUtil.setHost(serviceAddress.getHost());
        }
        for (Store s : mps.getServiceEnvironment().listStores()) {
            try {
                ServletDebugUtil.info(this, "updating store table for " + s);
                mps.processStoreCheck(s);
            } catch (Throwable e) {
                ServletDebugUtil.error(this, "could not update table for store " + s, e);
                if (ServletDebugUtil.isEnabled()) {
                    e.printStackTrace();
                }
            }
        }

        ServiceEnvironmentImpl env = (ServiceEnvironmentImpl) getEnvironment();

        MyLoggingFacade logger = env.getMyLogger();
        logger.info("Cleaning up incomplete client registrations");


        if (OA4MPServlet.transactionCleanup == null) {
            LockingCleanup lc = new LockingCleanup<>(logger, "transaction cleanup");
            lc.setStopThread(false);
            lc.setStore(env.getTransactionStore());
            lc.addRetentionPolicy(new ValidTimestampPolicy());
            OA4MPServlet.transactionCleanup = lc; // set it in the servlet

        }


        AbstractCLIApprover.ClientApprovalThread caThread = OA4MPServlet.caThread;
        if (caThread != null && !caThread.isAlive()) {
            caThread.setStopThread(false);
            caThread.start();
        }

        KeyPairPopulationThread kpt = OA4MPServlet.kpt;
        if (kpt != null && !kpt.isAlive()) {
            kpt.setStopThread(false);
            kpt.start();
        }

        try {
            setupNotifiers();
        } catch (Throwable e) {
            e.printStackTrace(); // uuuugly but if init did not complete, there may be no logging
            // AND Tomcat seems to eat certain exceptions and squirrels them away so at least a few
            // times (due to missing java mail jar) we had a silent error here and the servlet
            // was not initialized and behaved very strangely (since it did not finish OA2 load).

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
