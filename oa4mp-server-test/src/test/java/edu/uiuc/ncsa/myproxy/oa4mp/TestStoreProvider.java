package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.TransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
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
