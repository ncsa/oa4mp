package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ClaimSourceFactoryImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.TokenExchangeRecordRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.OA4MPServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl.ClientConverter;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSourceFactory;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.functions.FStack;
import edu.uiuc.ncsa.qdl.module.MIStack;
import edu.uiuc.ncsa.qdl.module.MTStack;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.state.StateUtils;
import edu.uiuc.ncsa.qdl.variables.VStack;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.storage.ListeningStoreInterface;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;
import edu.uiuc.ncsa.security.storage.events.LastAccessedThread;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import javax.servlet.ServletException;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.AbstractAccessTokenServlet2.txRecordCleanup;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/15/14 at  12:06 PM
 */
public class OA2ServletInitializer extends OA4MPServletInitializer {
    @Override
    public ExceptionHandler getExceptionHandler() {
        if (exceptionHandler == null) {
            exceptionHandler = new OA2ExceptionHandler(getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

    @Override
    protected NewClientNotifier createNewClientNotifier(MailUtil mailUtil, MyLoggingFacade logger) {
        return new OA2NewClientNotifier(mailUtil, logger);
    }

    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        super.init();
        // 12/14/2021 log4shell vulnerability. This should ensure that no dependency
        // can even try to do lookups.
        System.setProperty("log4j2.formatMsgNoLookups", "true");
        System.setProperty("LOG4J_FORMAT_MSG_NO_LOOKUPS", "true");

        OA2SE oa2SE = (OA2SE) getEnvironment();
        DebugUtil.setInstance(oa2SE.getDebugger()); // sets global debugger.
        DebugUtil.setPrintTS(oa2SE.isPrintTSInDebug());
        // Let the older myproxy connection clean up use alarms.
        if (MyProxyDelegationServlet.myproxyConnectionCleanup != null) {
            if (oa2SE.hasCleanupAlarms()) {
                MyProxyDelegationServlet.myproxyConnectionCleanup.setAlarms(oa2SE.getCleanupAlarms());
            } else {
                MyProxyDelegationServlet.myproxyConnectionCleanup.setCleanupInterval(oa2SE.getCleanupInterval());
            }
        }
        if (oa2SE.isMonitorEnabled() && MyProxyDelegationServlet.lastAccessedThread == null) {
            // Note that the event listener cannot be in the same thread as the updater since they whole
            // system freezes for every item update. 
            LastAccessedEventListener lastAccessedEventListener = new LastAccessedEventListener();
            LastAccessedThread lastAccessedThread = new LastAccessedThread("last accessed monitor", oa2SE.getMyLogger(), lastAccessedEventListener);
            addMonitoredStores(oa2SE, lastAccessedEventListener);
            lastAccessedThread.setCleanupInterval(oa2SE.getCleanupInterval());
            lastAccessedThread.setAlarms(oa2SE.getMonitorAlarms());
            lastAccessedThread.setStopThread(false);
            lastAccessedThread.start();
            //       oa2SE.getVOStore();
        }
        if (oa2SE.isRefreshTokenEnabled()) {
            MyProxyDelegationServlet.transactionCleanup.getRetentionPolicies().clear(); // We need a different set of policies than the original one.
            if (oa2SE.hasCleanupAlarms()) {
                MyProxyDelegationServlet.transactionCleanup.setAlarms(oa2SE.getCleanupAlarms());
                DebugUtil.trace(this, "setting transaction cleanup alarms " + oa2SE.getCleanupAlarms());
            } else {
                MyProxyDelegationServlet.transactionCleanup.setCleanupInterval(oa2SE.getCleanupInterval());
                DebugUtil.trace(this, "setting transaction cleanup interval to " + oa2SE.getCleanupInterval() + " ms.");
            }
            MyProxyDelegationServlet.transactionCleanup.addRetentionPolicy(
                    new RefreshTokenRetentionPolicy(
                            (RefreshTokenStore) oa2SE.getTransactionStore(),
                            oa2SE.getTxStore(),
                            oa2SE.getServiceAddress().toString(),
                            oa2SE.isSafeGC()));
            MyProxyDelegationServlet.transactionCleanup.setEnabledLocking(oa2SE.isCleanupLockingEnabled());
            MyProxyDelegationServlet.transactionCleanup.setStopThread(false);
            MyProxyDelegationServlet.transactionCleanup.start(); // start it here.
            oa2SE.getMyLogger().info("Started refresh token cleanup thread with interval " + oa2SE.getCleanupInterval());
        }
        if (!ClaimSourceFactory.isFactorySet()) {
            ClaimSourceFactory.setFactory(new ClaimSourceFactoryImpl());
        }
        if (txRecordCleanup == null) {
            LockingCleanup lc = new LockingCleanup(getEnvironment().getMyLogger(), "TX record cleanup");
            //txRecordCleanup = new Cleanup<>(getEnvironment().getMyLogger(), "TX record cleanup");
            lc.setStore(oa2SE.getTxStore());
            if (oa2SE.hasCleanupAlarms()) {
                lc.setAlarms(oa2SE.getCleanupAlarms());
                DebugUtil.trace(this, "setting tx record cleanup alarms to " + oa2SE.getCleanupAlarms());
            } else {
                lc.setCleanupInterval(oa2SE.getCleanupInterval());
                DebugUtil.trace(this, "setting tx record cleanup interval to " + oa2SE.getCleanupInterval() + " ms.");
            }
            lc.setEnabledLocking(oa2SE.isCleanupLockingEnabled());
            lc.setStopThread(false);
            //txRecordCleanup.setMap(oa2SE.getTxStore());
            lc.addRetentionPolicy(new TokenExchangeRecordRetentionPolicy(oa2SE.getServiceAddress().toString(), oa2SE.isSafeGC()));
            txRecordCleanup = lc;
            txRecordCleanup.start();
            oa2SE.getMyLogger().info("Starting token exchange record store cleanup thread with interval " + oa2SE.getCleanupInterval());
        }

        try {
            SATFactory.setAdminClientConverter(AdminClientStoreProviders.getAdminClientConverter());
            SATFactory.setClientConverter((ClientConverter<? extends Client>) oa2SE.getClientStore().getMapConverter());
        } catch (Exception e) {
            e.printStackTrace();
        }
        // QDL stuff. Make sure the factory returns the right state object
        StateUtils.setFactory(new StateUtils() {
            @Override
            public State create() {
                return new OA2State(
                        new VStack(),
                        new OpEvaluator(),
                        MetaEvaluator.getInstance(),
                        new FStack(),
                        new MTStack(),
                        new MIStack(),
                        null, // no logging at least for now
                        true,
                        true,
                        false,
                        true,
                        null); // default in server mode, but can be overridden later
            }
        });
    }
    protected void addMonitoredStores(OA2SE oa2SE, LastAccessedEventListener lastAccessedEventListener){
        ((ListeningStoreInterface) oa2SE.getClientStore()).addLastAccessedEventListener(lastAccessedEventListener);
        ((ListeningStoreInterface) oa2SE.getAdminClientStore()).addLastAccessedEventListener(lastAccessedEventListener);
        ((ListeningStoreInterface) oa2SE.getVOStore()).addLastAccessedEventListener(lastAccessedEventListener);
    }
}
