package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/21 at  11:47 AM
 */
public class CLCModule extends JavaModule {
    public CLCModule() {
    }

    public CLCModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        CLCModule clcModule = new CLCModule(URI.create("oa2:/qdl/oidc/client"), "clc");
        CLC clc = new CLC();

        funcs = new ArrayList<>();
        funcs.add(clc.new InitMethod());
        funcs.add(clc.new Access());
        funcs.add(clc.new InitMethod());
        funcs.add(clc.new Grant());
        funcs.add(clc.new CreateURI());
        funcs.add(clc.new Refresh());
        funcs.add(clc.new Revoke());
        funcs.add(clc.new Exchange());
        funcs.add(clc.new DeviceFlow());
        funcs.add(clc.new Introspect());
        clcModule.addFunctions(funcs);
        if (state != null) {
            clcModule.init(state);
        }
        return clcModule;
    }

    @Override
    public List<String> getDescription() {
        if (descr.isEmpty()) {
            descr.add("Module for the CLC (command line client). This allows you to do OAuth from QDL.");

        }
        return descr;
    }

    List<String> descr = new ArrayList<>();

}
