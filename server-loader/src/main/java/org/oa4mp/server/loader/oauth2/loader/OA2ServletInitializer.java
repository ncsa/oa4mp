package org.oa4mp.server.loader.oauth2.loader;

import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.claims.ClaimSourceFactoryImpl;
import org.oa4mp.server.loader.oauth2.servlet.MultiAuthServlet;
import org.oa4mp.server.loader.oauth2.servlet.OA2ExceptionHandler;
import org.oa4mp.server.loader.oauth2.servlet.TokenExchangeRecordRetentionPolicy;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenRetentionPolicy;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenStore;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.oa4mp.server.api.admin.adminClient.AdminClientStoreProviders;
import org.oa4mp.server.api.admin.things.SATFactory;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.api.storage.servlet.OA4MPServletInitializer;
import org.oa4mp.server.api.util.NewClientNotifier;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.ClientConverter;
import org.oa4mp.delegation.server.server.claims.ClaimSourceFactory;
import org.oa4mp.delegation.server.storage.upkeep.UpkeepThread;
import org.qdl_lang.evaluate.MetaEvaluator;
import org.qdl_lang.evaluate.OpEvaluator;
import org.qdl_lang.functions.FStack;
import org.qdl_lang.expressions.module.MIStack;
import org.qdl_lang.expressions.module.MTStack;
import org.qdl_lang.state.State;
import org.qdl_lang.state.StateUtils;
import org.qdl_lang.variables.VStack;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.events.LastAccessedEventListener;
import edu.uiuc.ncsa.security.storage.events.LastAccessedThread;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.List;

import static org.oa4mp.server.loader.oauth2.servlet.AbstractAccessTokenServlet2.txRecordCleanup;

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
        OA2Scopes.ScopeUtil.setBasicScopes(oa2SE.getScopes());
        if (oa2SE.getClientStore() instanceof SQLStore) {
            if (((SQLStore) oa2SE.getClientStore()).getConnectionPool() instanceof DerbyConnectionPool) {
                DerbyConnectionPool dcp = (DerbyConnectionPool) ((SQLStore) oa2SE.getClientStore()).getConnectionPool();
                if (dcp.getConnectionParameters().isCreateOne()) {
                    dcp.createStore();
                }
            }
        }
        DebugUtil.setInstance(oa2SE.getDebugger()); // sets global debugger.
        DebugUtil.setPrintTS(oa2SE.isPrintTSInDebug());
        // Let the older myproxy connection clean up use alarms.
   /*     if (OA4MPServlet.myproxyConnectionCleanup != null) {
            if (oa2SE.hasCleanupAlarms()) {
                OA4MPServlet.myproxyConnectionCleanup.setAlarms(oa2SE.getCleanupAlarms());
            } else {
                OA4MPServlet.myproxyConnectionCleanup.setCleanupInterval(oa2SE.getCleanupInterval());
            }
        }*/
        if (oa2SE.isMonitorEnabled() && OA4MPServlet.lastAccessedThread == null) {
            // Note that the event listener cannot be in the same thread as the updater since they whole
            // system freezes for every item update. 
            LastAccessedEventListener lastAccessedEventListener = new LastAccessedEventListener();
            String name = "last accessed monitor";
            LastAccessedThread lastAccessedThread = new LastAccessedThread(name, oa2SE.getMyLogger(), lastAccessedEventListener);
            // This is too verbose. Logs eventually can fill up with messages saying its doing nothing.
            // Only enable if debugging the last access thread
            //lastAccessedThread.setDebugOn(true);
            addMonitoredStores(oa2SE, lastAccessedEventListener);
            if (oa2SE.hasMonitorAlarams()) {
                lastAccessedThread.setAlarms(oa2SE.getMonitorAlarms());
                DebugUtil.trace(this, "starting \"" + name + "\" with alarms:" + oa2SE.getMonitorAlarms());
            } else {
                lastAccessedThread.setCleanupInterval(oa2SE.getMonitorInterval()); // there is always a default clenup interval
                DebugUtil.trace(this, "starting \"" + name + "\" with interval:" + oa2SE.getMonitorInterval() + " ms.");
            }
            lastAccessedThread.setStopThread(false);
            lastAccessedThread.start();
        }
        if (MultiAuthServlet.upkeepThreadList == null) {
            List<UpkeepThread> upkeepThreads = new ArrayList<>();
            for (Store store : oa2SE.getAllStores()) {
                if (store instanceof MonitoredStoreInterface) {
                    MonitoredStoreInterface MonitoredStoreInterface = (MonitoredStoreInterface) store;
                    if (MonitoredStoreInterface.getUpkeepConfiguration() != null && MonitoredStoreInterface.getUpkeepConfiguration().isEnabled()) {
                        UpkeepThread upkeepThread = new UpkeepThread("upkeep thread for " + MonitoredStoreInterface.getClass().getSimpleName(),
                                oa2SE, MonitoredStoreInterface);
                        upkeepThread.setStopThread(false);
                        upkeepThread.start();
                        upkeepThreads.add(upkeepThread);
                    }
                }
            }
            MultiAuthServlet.upkeepThreadList = upkeepThreads;
        }

        if (oa2SE.isRefreshTokenEnabled()) {
            OA4MPServlet.transactionCleanup.getRetentionPolicies().clear(); // We need a different set of policies than the original one.
            if (oa2SE.hasCleanupAlarms()) {
                OA4MPServlet.transactionCleanup.setAlarms(oa2SE.getCleanupAlarms());
                DebugUtil.trace(this, "setting transaction cleanup alarms " + oa2SE.getCleanupAlarms());
            } else {
                OA4MPServlet.transactionCleanup.setCleanupInterval(oa2SE.getCleanupInterval());
                DebugUtil.trace(this, "setting transaction cleanup interval to " + oa2SE.getCleanupInterval() + " ms.");
            }
            OA4MPServlet.transactionCleanup.addRetentionPolicy(
                    new RefreshTokenRetentionPolicy(
                            (RefreshTokenStore) oa2SE.getTransactionStore(),
                            oa2SE.getTxStore(),
                            oa2SE.getServiceAddress().toString(),
                            oa2SE.isSafeGC()));
            OA4MPServlet.transactionCleanup.setEnabledLocking(oa2SE.isCleanupLockingEnabled());
            OA4MPServlet.transactionCleanup.setFailOnError(oa2SE.isCleanupFailOnErrors());
            OA4MPServlet.transactionCleanup.setStopThread(false);
            OA4MPServlet.transactionCleanup.start(); // start it here.
            oa2SE.getMyLogger().info("Started refresh token cleanup thread with interval " + oa2SE.getCleanupInterval() + " ms.");
        }
        if (!ClaimSourceFactory.isFactorySet()) {
            ClaimSourceFactory.setFactory(new ClaimSourceFactoryImpl());
        }
        if (txRecordCleanup == null) {
            String name = "TX record cleanup";
            LockingCleanup lc = new LockingCleanup(getEnvironment().getMyLogger(), name);
            //txRecordCleanup = new Cleanup<>(getEnvironment().getMyLogger(), "TX record cleanup");
            lc.setStore(oa2SE.getTxStore());
            if (oa2SE.hasCleanupAlarms()) {
                lc.setAlarms(oa2SE.getCleanupAlarms());
                DebugUtil.trace(this, "setting \"" + name + "\" alarms to " + oa2SE.getCleanupAlarms());
            } else {
                lc.setCleanupInterval(oa2SE.getCleanupInterval());
                DebugUtil.trace(this, "setting \"" + name + "\" interval to " + oa2SE.getCleanupInterval() + " ms.");
            }
            lc.setEnabledLocking(oa2SE.isCleanupLockingEnabled());
            lc.setFailOnError(oa2SE.isCleanupFailOnErrors());
            lc.setStopThread(false);
            //txRecordCleanup.setMap(oa2SE.getTxStore());
            lc.addRetentionPolicy(new TokenExchangeRecordRetentionPolicy(oa2SE.getServiceAddress().toString(), oa2SE.isSafeGC()));
            txRecordCleanup = lc;
            txRecordCleanup.start();
            oa2SE.getMyLogger().info("Starting token exchange record store cleanup thread with interval " + oa2SE.getCleanupInterval() + " ms.");
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
                OA2State ss = new OA2State(
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
                ss.setOa2se(oa2SE);
                return ss;
            }
        });
    }

    protected void addMonitoredStores(OA2SE oa2SE, LastAccessedEventListener lastAccessedEventListener) {
        for (Store store : oa2SE.getAllStores()) {
            if (store instanceof MonitoredStoreInterface) {
                ((MonitoredStoreInterface) store).addLastAccessedEventListener(lastAccessedEventListener);
            }
        }
    }
}
