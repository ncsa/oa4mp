package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ClaimSourceFactoryImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.OA4MPServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
import edu.uiuc.ncsa.qdl.evaluate.MetaEvaluator;
import edu.uiuc.ncsa.qdl.evaluate.OpEvaluator;
import edu.uiuc.ncsa.qdl.module.ModuleMap;
import edu.uiuc.ncsa.qdl.state.ImportManager;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.state.StateUtils;
import edu.uiuc.ncsa.qdl.state.SymbolStack;
import edu.uiuc.ncsa.qdl.statements.FunctionTable;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceFactory;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import javax.servlet.ServletException;
import java.sql.SQLException;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet.TokenExchangeRecordRetentionPolicy;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ATServlet.txRecordCleanup;

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
        OA2SE oa2SE = (OA2SE) getEnvironment();

        MyProxyDelegationServlet mps = (MyProxyDelegationServlet) getServlet();
        try {
            //mps.storeUpdates();
            mps.processStoreCheck(oa2SE.getPermissionStore());
            mps.processStoreCheck(oa2SE.getAdminClientStore());
            mps.processStoreCheck(oa2SE.getTxStore());
        } catch (SQLException e) {
            if (DebugUtil.isEnabled()) {
                e.printStackTrace();
            }
            throw new ServletException("Could not update table", e);
        }
        if (oa2SE.isRefreshTokenEnabled()) {
            MyProxyDelegationServlet.transactionCleanup.getRetentionPolicies().clear(); // We need a different set of policies than the original one.
            MyProxyDelegationServlet.transactionCleanup.addRetentionPolicy(
                    new RefreshTokenRetentionPolicy(
                            (RefreshTokenStore) oa2SE.getTransactionStore(),
                            oa2SE.getServiceAddress().toString(),
                            oa2SE.isSafeGC()));
            oa2SE.getMyLogger().info("Initialized refresh token cleanup thread");
        }
        if (!ClaimSourceFactory.isFactorySet()) {
            ClaimSourceFactory.setFactory(new ClaimSourceFactoryImpl());
        }
        if (txRecordCleanup == null) {

            txRecordCleanup = new Cleanup<>(getEnvironment().getMyLogger());
            txRecordCleanup.setStopThread(false);
            txRecordCleanup.setMap(oa2SE.getTxStore());
            txRecordCleanup.addRetentionPolicy(new TokenExchangeRecordRetentionPolicy(oa2SE.getServiceAddress().toString(), oa2SE.isSafeGC()));
            txRecordCleanup.start();
            oa2SE.getMyLogger().info("Starting token exchange record store cleanup thread");
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
                return new OA2State(ImportManager.getResolver(),
                        new SymbolStack(),
                        new OpEvaluator(),
                        MetaEvaluator.getInstance(),
                        new FunctionTable(),
                        new ModuleMap(),
                        null, // no logging at least for now
                        true,
                        false); // default in server mode, but can be overridden later
            }
        });
    }

}
