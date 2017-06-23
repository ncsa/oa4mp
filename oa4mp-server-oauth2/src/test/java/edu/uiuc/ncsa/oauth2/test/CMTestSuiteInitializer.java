package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.loader.COLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractBootstrapper;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;

import static edu.uiuc.ncsa.myproxy.oa4mp.TestUtils.findConfigNode;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  12:25 PM
 */
public class CMTestSuiteInitializer extends TestSuiteInitializer {
    public CMTestSuiteInitializer(AbstractBootstrapper bootstrapper) {
        super(bootstrapper);
    }

    @Override
    protected TestStoreProvider2 getTSP(final String namedNode) {
        return new CMTestStoreProvider() {
                  COLoader loader;

                  @Override
                  public ConfigurationLoader<? extends ServiceEnvironment> getConfigLoader() {
                      if (loader == null) {
                          loader = new COLoader(findConfigNode(namedNode));
                      }
                      return loader;
                  }

              };
    }
}
