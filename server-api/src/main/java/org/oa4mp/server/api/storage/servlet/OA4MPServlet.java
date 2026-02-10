package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugConstants;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.servlet.HeaderUtils;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.events.LastAccessedThread;
import edu.uiuc.ncsa.security.util.pkcs.KeyPairPopulationThread;
import net.sf.json.JSONArray;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.common.servlet.TransactionFilter;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.UnapprovedClientException;
import org.oa4mp.delegation.server.issuers.AGIssuer;
import org.oa4mp.delegation.server.issuers.ATIssuer;
import org.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.server.api.ServiceEnvironment;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.util.AbstractCLIApprover;
import org.oa4mp.server.api.util.ClientDebugUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;

import static org.oa4mp.delegation.server.OA2Constants.OA4MP_TOKEN_SIGNING_KEY_ID;
import static org.oa4mp.server.api.ServiceConstantKeys.CONSUMER_KEY;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  3:46:53 PM
 */
// Formerly known as MyProxydelegationServlet Super class for all servlets in OA4MP.
public abstract class OA4MPServlet extends EnvServlet implements TransactionFilter {
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

    public static LastAccessedThread lastAccessedThread = null;



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
        if (caThread != null) {
            caThread.setStopThread(true);
        }
        if (kpt != null) {
            kpt.setStopThread(true);
        }
        if(lastAccessedThread != null){
            lastAccessedThread.setStopThread(true);
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
        state.getResponse().setHeader("Cache-Control", "no-store");
    }


    /**
     * Utility to extract all of the parameters from a request. Since the parameters are all
     * string arrays, this takes a little finagling. Generally we do not support multiple values
     * for parameters, so taking the first is reasonable.
     *
     * @param req
     * @return
     */
    public static Map<String, String> getFirstParameters(HttpServletRequest req) {
        return HeaderUtils.getFirstParameters(req);
    }

    /**
     * Gets the first values of the parameter with the give key or null if no such value.
     * @param req
     * @param key
     * @return
     */
    public String getFirstParameterValue(HttpServletRequest req, String key){
        return HeaderUtils.getFirstParameterValue(req, key);
    }
    /**
     * Just for low-level debugging.
     *
     * @param x
     */
    public void say(String x) {
        System.out.println(getClass().getSimpleName() + ": " + x);
    }

    /**
     * Given a client id, check if there is an associated admin client and if so, check
     * the status of said admin client. This way if an admin client has been revoked, e.g.,
     * all clients are immediately invalidated. This returns no value, it simply throws
     * an exception if the admin client is invalid.
     * @param clientID
     */
    // Fix https://jira.ncsa.illinois.edu/browse/CIL-2278 by centralizing it and making sure *every* access
    // point is checked.
    public void checkAdminClientStatus(Identifier clientID) {
        List<Identifier> adminIDs = getServiceEnvironment().getPermissionStore().getAdmins(clientID);
        if (adminIDs == null || adminIDs.size() == 0) {
            return; // nix to do
        }
        for (Identifier adminID : adminIDs) {
            if (!getServiceEnvironment().getClientApprovalStore().isApproved(adminID)) {
                throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT,
                        "Admin client is not approved , access denied",
                        HttpStatus.SC_UNAUTHORIZED, null);
            }
        }
    }
    /**
     * Checks if the signing key ID is in the request and if so, adds it to the list of key ids.
     * Noe that this allows for repeated ids but not if they are adjacent, so
     * <pre>ABCACAC</pre>
     * is fine, but not
     * <pre>ABCC</pre>
     * This way if a token is refreshed/exchanged repeatedly witht he same requested key, the list of keys does not
     * just turn into a huge string of the same thing like
     * <pre>ABCCCCCCCCCCCC</pre>
     * @param request
     * @param serviceTransaction
     */
    public static void findSigningKey(HttpServletRequest request, ServiceTransaction serviceTransaction) {

        if(request.getParameterMap().containsKey(OA4MP_TOKEN_SIGNING_KEY_ID)) {
            Object ooo = request.getParameterMap().get(OA4MP_TOKEN_SIGNING_KEY_ID);
            JSONArray aaa = serviceTransaction.getSigningKeyIds();

            if(ooo instanceof String[]) {
                for(String s : (String[])ooo) {
                    if(aaa.isEmpty()){
                     aaa.add(s);
                    }else {
                        if (!aaa.get(aaa.size() - 1).equals(s)) {
                            aaa.add(s);
                        }
                    }
                }
            }else{
                if(ooo instanceof String) {
                    if(!aaa.get(aaa.size()-1).equals(ooo)) {
                        aaa.add(ooo);
                    }
                }
            }
            serviceTransaction.setSigningKeyIds(aaa);
        }
    }
}
