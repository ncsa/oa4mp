package org.oa4mp.server.test;

import org.oa4mp.server.test.AbstractTestSuiteInitializer;
import org.oa4mp.server.test.TestStoreProviderInterface;
import org.oa4mp.server.test.TestUtils;
import org.oa4mp.server.loader.oauth2.loader.OA2ConfigurationLoader;
import org.oa4mp.server.api.ServiceEnvironment;
import org.oa4mp.server.api.admin.adminClient.AdminClientStoreProviders;
import org.oa4mp.server.api.admin.things.SATFactory;
import org.oa4mp.server.api.storage.servlet.AbstractBootstrapper;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.storage.clients.ClientConverter;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;

import static org.oa4mp.server.test.TestUtils.findConfigNode;

/**
 * Initializing the test suite has turned into such a large affair that the logic
 * really has to be encapsulated.
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  11:06 AM
 */
public class TestSuiteInitializer extends AbstractTestSuiteInitializer {
    public TestSuiteInitializer(AbstractBootstrapper bootstrapper) {
        super(bootstrapper);
    }

    @Override
    public TestStoreProvider2 getTSP(final String namedNode) {
        return new TestStoreProvider2() {
            OA2ConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA2ConfigurationLoader(findConfigNode(namedNode));
                }
                return loader;
            }

        };

    }

    @Override
    public String getAggregateStoreConfigName() {
        return getFileStoreConfigName();
    }

    @Override
    public String getFileStoreConfigName() {
        return "oa4mp.oa2.derby.filestore";
    }

    public String getOLDFileStoreConfigName() {
         return "oa4mp.oa2.fileStore";
     }
    @Override
    public String getMemoryStoreConfigName() {
//        return "oa4mp.oa2.memory";
        return "oa4mp.oa2.derby.memory";
    }

    public String getExplicitMemoryStoreConfigName() {
        //  return "oa4mp.oa2.memory2";
        return "oa4mp.oa2.derby.memory";
    }

    @Override
    public String getMySQLStoreConfigName() {
        return "oa4mp.oa2.mysql";
    }

    @Override
    public String getPostgresStoreConfigName() {
        return "oa4mp.oa2.postgres";
    }

    @Override
    public String getDerbyStoreConfigName() {
        return "oa4mp.oa2.derby";
    }
     protected TestStoreProviderInterface  checkDerby(TestStoreProviderInterface tspi){
         // The memory store is derby and has to be created.
         try {
             if (tspi.getClientStore() instanceof SQLStore) {
                 if (((SQLStore) tspi.getClientStore()).getConnectionPool() instanceof DerbyConnectionPool) {
                     DerbyConnectionPool dcp = (DerbyConnectionPool) ((SQLStore) tspi.getClientStore()).getConnectionPool();
                     if (dcp.isMemoryStore() || dcp.isFileStore()) {
                         // have to create it.
                         System.out.println("TEST, starting Derby store create");
                         dcp.createStore();
                     }
                 }
             }

         } catch (Exception x) {
             x.printStackTrace();
             throw new GeneralException("could not get client store:" + x.getMessage());
         }
        return tspi;
     }
    @Override
    public void init() {
        TestUtils.setBootstrapper(getBootstrapper());
        TestStoreProviderInterface tspi = getTSP(getExplicitMemoryStoreConfigName());
        TestUtils.setMemoryStoreProvider(checkDerby(tspi));
        TestStoreProvider2 fsp = getTSP(getFileStoreConfigName()); // use this later to get its client converter. Any store would do.
        TestUtils.setFsStoreProvider(checkDerby(fsp));
        TestUtils.setOLDfsStoreProvider(getTSP(getOLDFileStoreConfigName()));
        TestUtils.setMySQLStoreProvider(getTSP(getMySQLStoreConfigName()));
        TestUtils.setPgStoreProvider(getTSP(getPostgresStoreConfigName()));
        TestUtils.setDerbyStoreProvider(getTSP(getDerbyStoreConfigName()));
        try {
            SATFactory.setAdminClientConverter(AdminClientStoreProviders.getAdminClientConverter());
            SATFactory.setClientConverter((ClientConverter<? extends Client>) fsp.getClientStore().getMapConverter());
        } catch (Exception e) {
            e.printStackTrace();
        }
        // setup QDL unit testing
        org.qdl_lang.TestUtils.set_instance(new QDLTestUtils());
    }

}
