package edu.uiuc.ncsa.oa2.qdl;


import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/31/20 at  11:05 AM
 */
public class ClientManagementModule extends JavaModule {
    public ClientManagementModule() {
    }

    protected ClientManagementModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        ClientManagementModule cmm = new ClientManagementModule(URI.create("oa2:/qdl/oidc/client/manage"), "cm");
        ClientCommands cc = new ClientCommands();
        if(state != null){
            cc.setLogger(state.getLogger());
        }
        funcs = new ArrayList<>();
        funcs.add(cc.new InitMethod());
        funcs.add(cc.new ReadClient());
        funcs.add(cc.new SaveClient());
        funcs.add(cc.new Search());
        funcs.add(cc.new Remove());
        funcs.add(cc.new Size());
        funcs.add(cc.new Keys());
        funcs.add(cc.new Approve());
        cmm.addFunctions(funcs);
        if(state != null){
            cmm.init(state);
        }
        return cmm;
    }
}
