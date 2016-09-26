package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import org.apache.commons.configuration.tree.ConfigurationNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  4:00 PM
 */
public abstract class TestStoreProvider {


    protected ConfigurationNode node;

    public abstract ConfigurationLoader getConfigLoader() ;

    public ServiceEnvironment getSE()  {
        if(se == null){
            se = (ServiceEnvironment)getConfigLoader().load();
        }
        return se;
    }
    ServiceEnvironment  se;


    public TransactionStore<? extends BasicTransaction> getTransactionStore() throws Exception {
        return  getSE().getTransactionStore();
    }


    public ClientStore<Client> getClientStore() throws Exception {
        return getSE().getClientStore();
    }

    public ClientApprovalStore<ClientApproval> getClientApprovalStore() throws Exception {
        return getSE().getClientApprovalStore();
    }


   public TokenForge getTokenForge() {
        return getSE().getTokenForge();
    }

}
