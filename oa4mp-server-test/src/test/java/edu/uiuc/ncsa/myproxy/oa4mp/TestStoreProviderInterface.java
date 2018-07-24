package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/25/17 at  1:23 PM
 */
public interface TestStoreProviderInterface {
    ConfigurationLoader getConfigLoader() ;

    ServiceEnvironment getSE();

    TransactionStore<? extends BasicTransaction> getTransactionStore() throws Exception;

    ClientStore<Client> getClientStore() throws Exception;

    ClientApprovalStore<ClientApproval> getClientApprovalStore() throws Exception;

    TokenForge getTokenForge();

    public PermissionsStore<Permission> getPermissionStore() throws Exception;

    public AdminClientStore<AdminClient> getAdminClientStore() throws Exception;
}
