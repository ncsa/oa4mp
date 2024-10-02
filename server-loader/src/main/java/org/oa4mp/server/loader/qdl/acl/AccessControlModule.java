package org.oa4mp.server.loader.qdl.acl;

import org.qdl_lang.extensions.JavaModule;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.module.Module;
import org.qdl_lang.state.State;

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

    public static final String NAMESPACE =  "oa4mp:/qdl/acl";
    @Override
    public Module newInstance(State state) {

        AccessControlModule accessControlModule = new AccessControlModule(URI.create(NAMESPACE), "acl");
        QDLACL qdlacl = new QDLACL();
        List<QDLFunction> funcs = new ArrayList<>();
        funcs.add(qdlacl.new AddToACL());
        funcs.add(qdlacl.new AddToACL2());
        funcs.add(qdlacl.new ACLReject());
        funcs.add(qdlacl.new ACLReject2());
        funcs.add(qdlacl.new CheckACL());
        funcs.add(qdlacl.new CheckACL2());
        accessControlModule.addFunctions(funcs);

        setupModule(accessControlModule);
        return accessControlModule;
    }
    List<String> descr = new ArrayList<>();

    @Override
    public List<String> getDescription() {
        if(descr.isEmpty()){
            descr.add("ACL (Access Control List) management for QDL scripts running under OA4MP.");
            descr.add("If you need access control, this module is required and should be loaded automatically.");
        }
        return descr;
    }

    @Override
    public void setDocumentation(List<String> documentation) {

    }
}
