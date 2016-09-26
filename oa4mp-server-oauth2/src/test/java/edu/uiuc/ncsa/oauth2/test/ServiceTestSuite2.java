package edu.uiuc.ncsa.oauth2.test;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/12 at  3:10 PM
 */

import edu.uiuc.ncsa.myproxy.oa4mp.ServiceConfigTest;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.aggregate.AGCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.aggregate.AGClientTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSClientTest;
import edu.uiuc.ncsa.myproxy.oa4mp.file.FSTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.memory.MTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.mysql.MySQLTransactionStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2Bootstrapper;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGCAStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGClientStoreTest;
import edu.uiuc.ncsa.myproxy.oa4mp.postgres.PGTransactionStoreTest;
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

@Suite.SuiteClasses({
        TokenTest2.class,
        AGClientTest.class,
        AGCAStoreTest.class,
   //     AGTransactionStoreTest.class,
        FSClientTest.class,
        FSCAStoreTest.class,
        FSTransactionStoreTest.class,
        MClientStoreTest.class,
        MCAStoreTest.class,
        MTransactionStoreTest.class,
        MySQLClientStoreTest.class,
        MySQLCAStoreTest.class,
        MySQLTransactionStoreTest.class,
        PGClientStoreTest.class,
        PGCAStoreTest.class,
        PGTransactionStoreTest.class,
        FileStoreTest.class,
        ServiceConfigTest.class,
        RefreshTokenStoreTest.class
})
public class ServiceTestSuite2 extends TestSuite {
    @BeforeClass
    public static void initialize() {
        TestUtils.setBootstrapper(new OA2Bootstrapper());
        setupMemoryTests();
        setupFSTests();
        setupMySQLTests();
        setupPGTests();
        setupAGTests();
    }


    protected static void setupMemoryTests() {
        TestUtils.setMemoryStoreProvider(new TestStoreProvider() {
            OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("oa4mp.oa2.memory"));
                }
                return loader;
            }

        });
    }

     public static void setupH2Tests(){
            TestUtils.setH2StoreProvider(new TestStoreProvider() {
                  OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("h2-oa2"));
                }
                return loader;
            }
            });

       }
    public static void setupDerbyTests(){
            TestUtils.setDerbyStoreProvider(new TestStoreProvider() {
                  OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("derby-oa2"));
                }
                return loader;
            }
            });
        // derby tests are in memory only. This creates the databases.
        //  /home/ncsa/dev/main/ncsa-security-all/myproxy/oa4mp-webapp/src/main/resources/derby.sql

       }

    protected static void setupFSTests() {
        TestUtils.setFsStoreProvider(new TestStoreProvider() {
            OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("oa4mp.oa2.fileStore"));
                }
                return loader;
            }
        });
    }

    public static void setupMySQLTests() {
        TestUtils.setMySQLStoreProvider((new TestStoreProvider() {
            OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("oa4mp.oa2.mysql"));
                }
                return loader;
            }
        }));
    }

    public static void setupPGTests() {
        TestUtils.setPgStoreProvider((new TestStoreProvider() {
            OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode("oa4mp.oa2.postgres"));
                }
                return loader;
            }
        }));
    }

    public static class AGTestStoreProvider extends TestStoreProvider {
        // Default environment is the filestore test. change as needed.
        OA2ConfigurationLoader loader;

        @Override
        public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
            if (loader == null) {
                loader = new OA2ConfigurationLoader(findConfigNode("oa4mp.oa2.fileStore"));
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

    // Invoke this one last since it has dependencies on all the others.
    public static void setupAGTests() {
        TestUtils.setAgStoreProvider(new AGTestStoreProvider());
    }
}
