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
        ClientManagementModule cmm = new ClientManagementModule(URI.create("oa4mp:/qdl/oidc/client/manage"), "cm");

        ClientManagementCommands cc = new ClientManagementCommands();
        cmm.setMetaClass(cc);
        ArrayList<QDLFunction> funcs = new ArrayList<>();
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
        setupModule(cmm);
        return cmm;
    }
    List<String> descr = new ArrayList<>();

    @Override
    public List<String> getDescription() {
        if(descr.isEmpty()){
            descr.add("Module for managing clients. This allows you to create, approve, edit etc. ");
            descr.add("Note that this is older, and you should use the newer store access modules, which ");
            descr.add("have much more complete support.");
        }
        return descr;
    }

}
