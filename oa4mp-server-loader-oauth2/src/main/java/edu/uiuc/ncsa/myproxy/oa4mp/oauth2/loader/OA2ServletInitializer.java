package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.LDAPScopeHandlerFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.OA4MPServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientNotifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.server.ScopeHandlerFactory;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import javax.servlet.ServletException;
import java.sql.SQLException;

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
    protected NewClientNotifier createNewClientNotifier(MailUtil mailUtil, MyLoggingFacade logger){
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

        } catch (SQLException e) {
            if (DebugUtil.isEnabled()) {
                e.printStackTrace();
            }
            throw new ServletException("Could not update table", e);
        }
        if (oa2SE.isRefreshTokenEnabled()) {
            MyProxyDelegationServlet.transactionCleanup.getRetentionPolicies().clear(); // We need a different set of policies than the original one.
            MyProxyDelegationServlet.transactionCleanup.addRetentionPolicy(new RefreshTokenRetentionPolicy((RefreshTokenStore) oa2SE.getTransactionStore()));
            oa2SE.getMyLogger().info("Initialized refresh token cleanup thread");
        }
        if (!ScopeHandlerFactory.isFactorySet()) {
            ScopeHandlerFactory.setFactory(new LDAPScopeHandlerFactory());
        }
    }

}
