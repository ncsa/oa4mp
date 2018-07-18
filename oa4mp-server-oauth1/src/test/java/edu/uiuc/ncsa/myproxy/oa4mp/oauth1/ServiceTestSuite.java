package edu.uiuc.ncsa.myproxy.oa4mp.oauth1;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import edu.uiuc.ncsa.myproxy.oa4mp.*;
import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPBootstrapper;
import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.server.storage.*;
import edu.uiuc.ncsa.security.delegation.storage.AggregateTransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.FileStoreTest;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.storage.impl.BasicTransaction;
import junit.framework.TestSuite;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;


/**
 * <p>Created by Jeff Gaynor<br>
 * on Nov 27, 2010 at  1:28:14 PM
 */
@RunWith(Suite.class)
/*
NOTE: the tests below are commented out so this runs from the command line with the full build,
which includes CILogon.
 */
@Suite.SuiteClasses({
        NewCAStoreTest.class,
        NewClientStoreTest.class,
        NewTransactionTest.class,
        TokenTest.class,
        FileStoreTest.class,
        ServiceConfigTest.class
})
public class ServiceTestSuite extends TestSuite {

    @BeforeClass
    public static void initialize() {
        TestSuiteInitializer tsi = new TestSuiteInitializer(new OA4MPBootstrapper());
        tsi.init();
    }

    public static class AGTestStoreProvider extends TestStoreProvider {

        OA4MPConfigurationLoader loader;
        String configName;

        public AGTestStoreProvider(String aggregateStoreConfigName) {
                         configName = aggregateStoreConfigName;
        }

        @Override
        public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
            if (loader == null) {
                loader = new OA4MPConfigurationLoader(findConfigNode(null, configName));
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

}
