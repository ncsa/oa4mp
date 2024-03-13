package edu.uiuc.ncsa.oa2.qdl.testUtils;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/11/24 at  7:59 AM
 */
public class TestUtilModule extends JavaModule {
    public TestUtilModule() {
    }

    public TestUtilModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        TestUtilModule m = new TestUtilModule(URI.create("oa2:/qdl/oidc/test/util"), "test_util");
        TestUtils testUtils = new TestUtils();
        m.setMetaClass(testUtils);
        funcs = new ArrayList<>();
        funcs.add(testUtils.new ComputeIDTLifetime());
        funcs.add(testUtils.new ComputeATLifetime());
        funcs.add(testUtils.new ComputeRTLifetime());
        funcs.add(testUtils.new ComputeGracePeriod());
        funcs.add(testUtils.new TimeToLong());

        m.addFunctions(funcs);
        if (state != null) {
            m.init(state);
        }
        return m;

    }

    @Override
    public List<String> getDescription() {
        List<String> a = new ArrayList<>();
        a.add("TestUtils is charged with making certain server-side utilities ");
        a.add("such as computing lifetimes of tokens, available to QDL scripts that");
        a.add("do testing. The logic for these is often complex and rewriting them");
        a.add("in QDL would just end up being a maintenance headache eventually.");
        return a;
    }

    /*
      CLCModule clcModule = new CLCModule(URI.create("oa2:/qdl/oidc/client"), "clc");
        CLC clc = new CLC();
       clcModule.setMetaClass(clc);
        funcs = new ArrayList<>();
        funcs.add(clc.new Access());
                clcModule.addFunctions(funcs);
        if (state != null) {
            clcModule.init(state);
        }
        setupModule(clcModule);
        return clcModule;

     */
}
