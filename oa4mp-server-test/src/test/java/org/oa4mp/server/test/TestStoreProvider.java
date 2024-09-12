package org.oa4mp.server.test;

import org.oa4mp.server.api.ServiceEnvironment;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import org.oa4mp.delegation.common.token.TokenForge;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  4:00 PM
 */
public abstract class TestStoreProvider implements TestStoreProviderInterface {


    protected ConfigurationNode node;

    @Override
    public ServiceEnvironment getSE()  {
        if(se == null){
            se = (ServiceEnvironment)getConfigLoader().load();
        }
        return se;
    }
    ServiceEnvironment  se;


    @Override
    public TransactionStore<? extends BasicTransaction> getTransactionStore() throws Exception {
        return  getSE().getTransactionStore();
    }


    @Override
    public ClientStore<Client> getClientStore() throws Exception {
        return getSE().getClientStore();
    }

    @Override
    public ClientApprovalStore<ClientApproval> getClientApprovalStore() throws Exception {
        return getSE().getClientApprovalStore();
    }


   @Override
   public TokenForge getTokenForge() {
        return getSE().getTokenForge();
    }

    @Override
    public AdminClientStore<AdminClient> getAdminClientStore() throws Exception {
        return null;
    }

    @Override
    public PermissionsStore<Permission> getPermissionStore() throws Exception {
        return null;
    }
}
