package edu.uiuc.ncsa.myproxy.oa4mp.qdl.acl;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/25/21 at  7:40 AM
 */
public class AccessControlModule extends JavaModule {
    public AccessControlModule() {
    }

    public AccessControlModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {

        AccessControlModule accessControlModule = new AccessControlModule(URI.create("oa2:/qdl/acl"), "acl");
        QDLACL qdlacl = new QDLACL();
        List<QDLFunction> funcs = new ArrayList<>();
        funcs.add(qdlacl.new AddToACL());
        funcs.add(qdlacl.new CheckACL());
        accessControlModule.addFunctions(funcs);

        return accessControlModule;
    }
}
