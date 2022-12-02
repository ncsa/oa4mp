package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.server.MyProxyServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.AbstractCLIApprover;
import edu.uiuc.ncsa.myproxy.oa4mp.server.util.ClientDebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.TransactionFilter;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.TransactionState;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cache;
import edu.uiuc.ncsa.security.core.cache.CachedObject;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugConstants;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairPopulationThread;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  3:46:53 PM
 */
public abstract class MyProxyDelegationServlet extends EnvServlet implements TransactionFilter {
    public static MetaDebugUtil createDebugger(BaseClient client) {
        if (client == null) return DebugUtil.getInstance();
        if (client.isDebugOn()) {
            MetaDebugUtil debugger = new ClientDebugUtil(client);
            debugger.setIsEnabled(true);
            debugger.setDebugLevel(DebugConstants.DEBUG_LEVEL_TRACE);
            debugger.setPrintTS(true); // just for this client
            return debugger;
        }
        return DebugUtil.getInstance();
    }

    /**
     * This is called after the response is received so that the system can get the approproate
     * transaction. Checks for the validity of the transaction should be done here too.
     *
     * @param iResponse@return
     */
    public abstract ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException;


    @Override
    public ServiceEnvironmentImpl loadProperties2() throws IOException {
        ServiceEnvironmentImpl se2 = super.loadProperties2();
        if (se2.isPollingEnabled()) {
            caThread = se2.getClientApprovalThread();
        }
        kpt = new KeyPairPopulationThread(se2.getKeyPairQueue());
        return se2;
    }

    public static Cleanup<String, BasicTransaction> transactionCleanup;

    public static Cleanup<Identifier, CachedObject> myproxyConnectionCleanup = null;


    public static Cache getMyproxyConnectionCache() {
        if (myproxyConnectionCache == null) {
            myproxyConnectionCache = new Cache();
        }
        return myproxyConnectionCache;
    }

    public static Cache myproxyConnectionCache;

    public static KeyPairPopulationThread kpt;


    public AGIssuer getAGI() throws IOException {
        return getServiceEnvironment().getAgIssuer();
    }

    protected ATIssuer getATI() throws IOException {
        return getServiceEnvironment().getAtIssuer();
    }


    public static ServiceEnvironment getServiceEnvironment() {
        return (ServiceEnvironment) getEnvironment();
    }

    public static List<MyProxyServiceFacade> getMyproxyServices() {
        return ((MyProxyServiceEnvironment) getEnvironment()).getMyProxyServices();
    }

    public void storeUpdates() throws IOException, SQLException {
        if (storeUpdatesDone) return; // run this once
        storeUpdatesDone = true;
        realStoreUpdates();
    }

    /**
     * If you have store updates that need to get done, put them in this method,
     * invoking super. Calls to this are managed by the servlet to make sure
     * nothing get called more than once.
     *
     * @throws IOException
     * @throws SQLException
     */
    protected void realStoreUpdates() throws IOException, SQLException {
        ServletDebugUtil.trace(this, "starting store updates");
        processStoreCheck(getTransactionStore());
        processStoreCheck(getServiceEnvironment().getClientStore());
        processStoreCheck(getServiceEnvironment().getClientApprovalStore());

    }


    public static AbstractCLIApprover.ClientApprovalThread caThread = null;

    protected void shutdownCleanup(Cleanup c) {
        if (c != null && !c.isStopThread()) {
            c.setStopThread(true); // Just in case...
            c.interrupt();
        }
    }

    @Override
    public void destroy() {
        super.destroy();
        shutdownCleanup(transactionCleanup);
        shutdownCleanup(myproxyConnectionCleanup);
        if (caThread != null) {
            caThread.setStopThread(true);
        }
        if (kpt != null) {
            kpt.setStopThread(true);
        }
    }

    public TransactionStore getTransactionStore() throws IOException {
        return getServiceEnvironment().getTransactionStore();
    }

    /**
     * Assumes that the client identifier is a parameter in the request.
     *
     * @param req
     * @return
     */
    public Client getClient(HttpServletRequest req) {
        return getClient(getGrantIDFromRequest(req));
    }

    protected ServiceTransaction getTransactionByGrantID(HttpServletRequest request) throws IOException {
        Identifier id = getGrantIDFromRequest(request);
        ServletDebugUtil.trace(this, "getting transaction from id \"" + id + "\"");
        ServiceTransaction t = (ServiceTransaction) getTransactionStore().get(id);
        ServletDebugUtil.trace(this, "got transaction \"" + t + "\"");

        return t;
    }

    protected Identifier getGrantIDFromRequest(HttpServletRequest req) {
        if (req.getParameter(CONST(CONSUMER_KEY)) == null) {
            throw new UnknownClientException("Error: no client identifier has been supplied. Have you registered this client with the service?");
        }
        return BasicIdentifier.newID(req.getParameter(CONST(CONSUMER_KEY)));

    }

    public Client getClient(Identifier identifier) {
        if (identifier == null) {
            throw new UnknownClientException("no client id");
        }
        Client c = getServiceEnvironment().getClientStore().get(identifier);
        if (c == null) {
            if (getServiceEnvironment().getClientStore().size() == 0) {
                // This tries to show if, perhaps, the wrong store wa loaded by printing out a little information about it.
                DebugUtil.trace(this, "CLIENT STORE HAS NO ENTRIES!");
                DebugUtil.trace(this, "client name is " + getServiceEnvironment().getClientStore().getClass().getSimpleName());
                DebugUtil.trace(this, "client store is a " + getServiceEnvironment().getClientStore());
            }
            String ww = "Unknown client: \"" + identifier.toString() + "\"  cannot be found.";
            warn(ww + " Client store is " + getServiceEnvironment().getClientStore());
            throw new UnknownClientException(ww + "  Is the value in the client config correct?", identifier);
        }
        checkClientApproval(c);
        return c;
    }


    public ServiceTransaction newTransaction() throws IOException {
        return getServiceEnvironment().getTransactionStore().create();
    }

    protected ServiceTransaction getTransaction(AuthorizationGrant grant) throws IOException {
        return (ServiceTransaction) getTransactionStore().get(grant);
    }

    /**
     * A utility to get the client from the authorization grant. This looks up the transaction
     *
     * @param authorizationGrant
     * @return
     */
    protected Client getClient(AuthorizationGrant authorizationGrant) throws IOException {
        ServiceTransaction transaction = getTransaction(authorizationGrant);
        return transaction.getClient();
    }

    /**
     * Checks if the client is approved. This should be done before each leg of the process
     *
     * @param client
     */
    public void checkClientApproval(BaseClient client) {
        ClientApproval clientApproval = getServiceEnvironment().getClientApprovalStore().get(client.getIdentifier());
        String ww = null;
        if (clientApproval == null) {
            // Generally the client should have an approval record auto-created with the right status
            // however, if an admin creates one manually,, there may not be such a record.
            // In that case, treat it as if the approval is still pending.
            ww = "The client with identifier \"" + client.getIdentifier() + "\" has not been approved. Request rejected. Please contact your administrator.";
        } else {
            switch (clientApproval.getStatus()) {
                case APPROVED:
                    // do nothing
                    return;
                case NONE:
                case PENDING:
                    ww = "The client with identifier \"" + client.getIdentifier() + "\" is pending approval. Request rejected. Please contact your administrator.";
                    break;
                case REVOKED:
                    ww = "The client with identifier \"" + client.getIdentifier() + "\" has been revoked. Request rejected. Please contact your administrator.";
                    break;
                case DENIED:
                    ww = "The client with identifier \"" + client.getIdentifier() + "\" has been denied. Request rejected. Please contact your administrator.";
                    break;
                default:
                    // In practice, if it gets here there is something seriously wrong with the internal state of this client.
                    ww = "The client with identifier \"" + client.getIdentifier() + "\" has unknown status. Request rejected. Please contact your administrator.";
            }
        }
        warn(ww);
        throw new UnapprovedClientException("Error: " + ww, client);
/*
        if (!getServiceEnvironment().getClientApprovalStore().isApproved(client.getIdentifier())) {
            String ww = "The client with identifier \"" + client.getIdentifier() + "\" has not been approved. Request rejected. Please contact your administrator.";
        }
*/
    }

    protected boolean isEmpty(String x) {
        return x == null || x.length() == 0;
    }


    /**
     * Note that if you override this, you should call super, which sets some security-related headers, but touches nothing else.
     *
     * @param state
     * @throws Throwable
     */
    @Override
    public void preprocess(TransactionState state) throws Throwable {
        //state.getResponse().setHeader("X-Frame-Options", "DENY");
    }

    @Override
    public void postprocess(TransactionState state) throws Throwable {
        state.getResponse().setHeader("X-Frame-Options", "DENY");
    }


    protected boolean hasMPConnection(Identifier identifier) {
        return getMyproxyConnectionCache().containsKey(identifier);
    }

    protected boolean hasMPConnection(ServiceTransaction transaction) {
        return hasMPConnection(transaction.getIdentifier());
    }

    protected MyProxyConnectable getMPConnection(ServiceTransaction transaction) {
        return getMPConnection(transaction.getIdentifier());
    }

    protected MyProxyConnectable getMPConnection(Identifier identifier) {
        return (MyProxyConnectable) getMyproxyConnectionCache().get(identifier).getValue();
    }

    /**
     * Utility to extract all of the parameters from a request. Since the parameters are all
     * string arrays, this takes a little finagling. Generally we do not support multiple values
     * for parameters, so taking the first is reasonable.
     *
     * @param req
     * @return
     */
    protected Map<String, String> getFirstParameters(HttpServletRequest req) {
        HashMap<String, String> map = new HashMap<>();
        for (Object key : req.getParameterMap().keySet()) {
            map.put(key.toString(), getFirstParameterValue(req, key.toString()));
        }
        return map;
    }

    /**
     * Just for low-level debugging.
     *
     * @param x
     */
    public void say(String x) {
        System.out.println(getClass().getSimpleName() + ": " + x);
    }

}
