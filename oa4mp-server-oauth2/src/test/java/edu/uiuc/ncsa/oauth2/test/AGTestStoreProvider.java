package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.server.storage.*;
import edu.uiuc.ncsa.security.delegation.storage.AggregateTransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.BasicTransaction;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  11:31 AM
 */
public class AGTestStoreProvider extends TestStoreProvider2 {
    public AGTestStoreProvider(String nodeName) {
        this.nodeName = nodeName;
    }

    String nodeName;
        // Default environment is the filestore test. change as needed.
        OA2ConfigurationLoader loader;

        @Override
        public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
            if (loader == null) {
                loader = new OA2ConfigurationLoader(findConfigNode(nodeName));
            }
            return loader;
        }

        AggregateCAStore<ClientApprovalStore> caStore;

        @Override
        public ClientApprovalStore<ClientApproval> getClientApprovalStore() throws Exception {
            if (caStore == null) {
                caStore = new AggregateCAStore<ClientApprovalStore>();
                caStore.addStore(TestUtils.getMemoryStoreProvider().getClientApprovalStore());
                caStore.addStore(TestUtils.getFsStoreProvider().getClientApprovalStore());
                caStore.addStore(TestUtils.getMySQLStoreProvider().getClientApprovalStore());
                caStore.addStore(TestUtils.getPgStoreProvider().getClientApprovalStore());
            }
            return caStore;
        }

        AggregateClientStore<ClientStore> clientStore;

        @Override
        public ClientStore<Client> getClientStore() throws Exception {
            if (clientStore == null) {
                clientStore = new AggregateClientStore<ClientStore>();
                clientStore.addStore(TestUtils.getMemoryStoreProvider().getClientStore());
                clientStore.addStore(TestUtils.getFsStoreProvider().getClientStore());
                clientStore.addStore(TestUtils.getMySQLStoreProvider().getClientStore());
                clientStore.addStore(TestUtils.getPgStoreProvider().getClientStore());
            }
            return clientStore;
        }

        AggregateTransactionStore<TransactionStore> transactionStore;

        @Override
        public TransactionStore<? extends BasicTransaction> getTransactionStore() throws Exception {
            if (transactionStore == null) {
                transactionStore = new AggregateTransactionStore<TransactionStore>();
                transactionStore.addStore(TestUtils.getMemoryStoreProvider().getTransactionStore());
                transactionStore.addStore(TestUtils.getFsStoreProvider().getTransactionStore());
                transactionStore.addStore(TestUtils.getMySQLStoreProvider().getTransactionStore());
                transactionStore.addStore(TestUtils.getPgStoreProvider().getTransactionStore());
            }
            return transactionStore;
        }
}
