package test;

import edu.uiuc.ncsa.myproxy.oa4mp.AbstractTestSuiteInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;

/**
 * Initializing the test suite has turned into such a large affair that the logic
 * really has to be encapsulated.
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  11:06 AM
 */
public class TestSuiteInitializer extends AbstractTestSuiteInitializer{
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
                    //loader = new OA2ConfigurationLoader(findConfigNode(namedNode));
                    loader = new COLoader(findConfigNode(namedNode));
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
        return "oa4mp.oa2.fileStore";
    }

    @Override
    public String getMemoryStoreConfigName() {
        return "oa4mp.oa2.memory";
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
    public void init() {
        TestUtils.setBootstrapper(getBootstrapper());
        TestUtils.setMemoryStoreProvider(getTSP(getMemoryStoreConfigName()));
        TestStoreProvider2 fsp = getTSP(getFileStoreConfigName()); // use this later to get its client converter. Any store would do.
        TestUtils.setFsStoreProvider(fsp);
        TestUtils.setMySQLStoreProvider(getTSP(getMySQLStoreConfigName()));
        TestUtils.setPgStoreProvider(getTSP(getPostgresStoreConfigName()));
      //  TestUtils.setAgStoreProvider(new AGTestStoreProvider(getAggregateStoreConfigName()));

        //TestUtils.setH2StoreProvider(getTSP(""h2-oa2");
        //TestUtils.setDerbyStoreProvider(getTSP(""derby-oa2");

        try {
            SATFactory.setAdminClientConverter(AdminClientStoreProviders.getAdminClientConverter());
            SATFactory.setClientConverter((ClientConverter<? extends Client>) fsp.getClientStore().getACConverter());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
