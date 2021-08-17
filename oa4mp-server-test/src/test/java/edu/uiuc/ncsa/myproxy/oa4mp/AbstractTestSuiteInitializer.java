package edu.uiuc.ncsa.myproxy.oa4mp;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;

/**
 * This will set up a test suite. The config file name getters allow you to specify the
 * name of the configuration in the configuration file. Generally you can just alias these
 * in that file rather than overriding the names in a class.
 * <p>Created by Jeff Gaynor<br>
 * on 10/27/17 at  3:50 PM
 */
public abstract class AbstractTestSuiteInitializer {
    public AbstractTestSuiteInitializer(AbstractBootstrapper bootstrapper) {
        this.bootstrapper = bootstrapper;
    }

    public AbstractBootstrapper getBootstrapper() {
        return bootstrapper;
    }

    public void setBootstrapper(AbstractBootstrapper bootstrapper) {
        this.bootstrapper = bootstrapper;
    }

    AbstractBootstrapper bootstrapper = null;

    public abstract TestStoreProviderInterface getTSP(final String namedNode);

    public abstract String getFileStoreConfigName();

    public abstract String getMemoryStoreConfigName();

    public abstract String getMySQLStoreConfigName();

    public abstract String getPostgresStoreConfigName();

    public abstract String getDerbyStoreConfigName();

    public abstract String getAggregateStoreConfigName();

    public abstract void init();
}
