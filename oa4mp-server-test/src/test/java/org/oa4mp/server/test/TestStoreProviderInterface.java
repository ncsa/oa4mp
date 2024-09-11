package org.oa4mp.server.test;

import org.oa4mp.server.api.ServiceEnvironment;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.token.TokenForge;

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
