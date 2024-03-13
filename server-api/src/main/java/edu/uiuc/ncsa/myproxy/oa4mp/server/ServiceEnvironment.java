package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.MyProxyServiceFacade;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.ATIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Logable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.servlet.UsernameTransformer;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.net.URI;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;

/**
 * This interface has the instances of various stores and other configurable information in it.
 * <p>Created by Jeff Gaynor<br>
 * on 4/13/12 at  10:40 AM
 */
public interface ServiceEnvironment extends Logable {

    public AuthorizationServletConfig getAuthorizationServletConfig();

    /**
     * Return a key pair for cert request generation, e.g. in limited proxy requests.
     *
     * @return
     */
    public KeyPair getKeyPair();

    // redundant from AbstractEnvironment, but need it for services in the interface.
    Map<String, String> getConstants();

    /**
     * Messages which may be displayed to the user, e.g., when authentication fails.
     *
     * @return
     */
    Map<String, String> getMessages();

    /**
     * Returns the current transaction store.
     *
     * @return
     */
    TransactionStore<ServiceTransaction> getTransactionStore();

    /**
     * List of known MyProxy servers. This list will be tried in order until either an operation]
     * succeeds or there is a {@link java.security.GeneralSecurityException}. Other exceptions
     * (such as network issues) are ignored.
     *
     * @return
     */

    List<MyProxyServiceFacade> getMyProxyServices();

    /**
     * The address for this server. Since hosts can have any of several aliases, automatic determination from
     * the servlet is usually a bad idea.
     *
     * @return
     */
    URI getServiceAddress();

    void setServiceAddress(URI serviceAddress);

    /**
     * The forge that creates delegation tokens for this service.
     *
     * @return
     */
    TokenForge getTokenForge();

    /**
     * The {@link edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer} that creates {@link edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant}s.
     *
     * @return
     */
    AGIssuer getAgIssuer();

    /**
     * The {@link edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer} that creates {@link edu.uiuc.ncsa.security.delegation.token.AccessToken}s.
     *
     * @return
     */

    ATIssuer getAtIssuer();

    /**
     * The {@link edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer} that creates the {@link edu.uiuc.ncsa.security.delegation.token.ProtectedAsset}s.
     *
     * @return
     */
    PAIssuer getPaIssuer();

    /**
     * Returns the current {@link ClientStore}.
     *
     * @return
     */
    ClientStore<Client> getClientStore();

    /**
     * Returns the {@link AdminClientStore}.
     * @return
     */
    AdminClientStore<AdminClient> getAdminClientStore();

    /**
     * returns the client approval store.
     *
     * @return
     */
    ClientApprovalStore<ClientApproval> getClientApprovalStore();

    /**
     * Returns the mail utility which, when configured, will send notifications for requests.
     *
     * @return
     */
    MailUtil getMailUtil();

    int getMaxAllowedNewClientRequests();

    UsernameTransformer getUsernameTransformer();

    void setUsernameTransformer(UsernameTransformer usernameTransformer);

    boolean isPingable();

    /**
     * List the current stores in this environment. Used at bootstrapping for various types of introspection.
     * @return
     */
    List<Store> listStores();

    PermissionsStore<Permission> getPermissionStore();
}
