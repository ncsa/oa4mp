package org.oa4mp.server.qdl;

import org.qdl_lang.extensions.JavaModule;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.module.Module;
import org.qdl_lang.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/22/21 at  11:47 AM
 */

// clc#init(config_file := '/home/ncsa/dev/csd/config/client-oa2.xml', 'localhost:test/qdl');
public class CLCModule extends JavaModule {
    public CLCModule() {
    }

    public CLCModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        CLCModule clcModule = new CLCModule(URI.create("oa4mp:/qdl/oidc/client"), "clc");
        CLC clc = new CLC();
       clcModule.setMetaClass(clc);
       ArrayList<QDLFunction> funcs = new ArrayList<>();
        funcs = new ArrayList<>();
        funcs.add(clc.new Access());
        funcs.add(clc.new AccessAT());
        funcs.add(clc.new AccessRT());
        funcs.add(clc.new ClearParam());
        funcs.add(clc.new CreateURI());
        funcs.add(clc.new GetCurrentURI());
        funcs.add(clc.new DeviceFlow());
        funcs.add(clc.new EchoHTTPRequest());
        funcs.add(clc.new EchoHttpResponse());
        funcs.add(clc.new Exchange());
        funcs.add(clc.new GetCert());
        funcs.add(clc.new GetClaim());
        funcs.add(clc.new GetParam());
        funcs.add(clc.new Grant());
        funcs.add(clc.new InitMethod());
        funcs.add(clc.new Introspect());
        funcs.add(clc.new JavaTrace());
        funcs.add(clc.new RFC7523());
        funcs.add(clc.new Read());
        funcs.add(clc.new Refresh());
        funcs.add(clc.new Revoke());
        funcs.add(clc.new SetParam());
        funcs.add(clc.new Tokens());
        funcs.add(clc.new UserInfo());
        funcs.add(clc.new VerboseOn());
        funcs.add(clc.new Write());
        clcModule.addFunctions(funcs);
        if (state != null) {
            clcModule.init(state);
        }
        setupModule(clcModule);
        return clcModule;
    }

    @Override
    public List<String> getDescription() {
        if (descr.isEmpty()) {
            descr.add("Module for the CLC (command line client). This allows you to do OAuth from QDL.");
            descr.add("Among other features, you can send multiple parameters as lists, e.g.");
            descr.add(" params. :=      {'org.oa4mp:/roles' : 'admin,all-user',       // sends as a string\n" +
                    "                   'org.oa4mp:/roles2' : ['admin2','all-user2'], // sends as a list of strings\n" +
                    "   'org.oa4mp:/tokens/access/lifetime' : 1000000,                // sends an integer\n" +
                    "                                 'sub' : 'jeff'}");
        }
        return descr;
    }

    List<String> descr = new ArrayList<>();

}
