package edu.uiuc.ncsa.myproxy.oa4mp.oauth1;

import edu.uiuc.ncsa.myproxy.oa4mp.AbstractTestSuiteInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.TestStoreProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/27/17 at  4:07 PM
 */
public class TestSuiteInitializer extends AbstractTestSuiteInitializer {
    public TestSuiteInitializer(AbstractBootstrapper bootstrapper) {
        super(bootstrapper);
    }

    @Override
    public String getAggregateStoreConfigName() {
        return getFileStoreConfigName();
    }

    @Override
    public TestStoreProvider getTSP(final String namedNode) {
        return new TestStoreProvider() {
            OA4MPConfigurationLoader loader;

            @Override
            public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                if (loader == null) {
                    loader = new OA4MPConfigurationLoader(findConfigNode(namedNode));
                }
                return loader;
            }

        };
    }

    @Override
    public String getFileStoreConfigName() {
        return "oa4mp.oa1.fileStore";
    }

    @Override
    public String getMemoryStoreConfigName() {
        return "oa4mp.oa1.memory";
    }

    @Override
    public String getMySQLStoreConfigName() {
        return "oa4mp.oa1.mysql";
    }

    @Override
    public String getPostgresStoreConfigName() {
        return "oa4mp.oa1.postgres";
    }

    @Override
    public void init() {
        TestUtils.setBootstrapper(getBootstrapper());
           TestUtils.setMemoryStoreProvider(getTSP(getMemoryStoreConfigName()));
           TestStoreProvider fsp = getTSP(getFileStoreConfigName()); // use this later to get its client converter. Any store would do.
           TestUtils.setFsStoreProvider(fsp);
           TestUtils.setMySQLStoreProvider(getTSP(getMySQLStoreConfigName()));
           TestUtils.setPgStoreProvider(getTSP(getPostgresStoreConfigName()));
           TestUtils.setAgStoreProvider(new ServiceTestSuite.AGTestStoreProvider(getAggregateStoreConfigName()));

    }
}
