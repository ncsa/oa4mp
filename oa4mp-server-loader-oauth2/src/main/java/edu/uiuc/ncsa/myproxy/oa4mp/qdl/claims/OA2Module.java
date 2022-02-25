package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;


import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  5:49 AM
 */
public class OA2Module extends JavaModule {
    public OA2Module() {
    }

    protected OA2Module(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        OA2Module oa2Module = new OA2Module(URI.create("oa2:/qdl/oidc/claims"), "claims");
        ArrayList<QDLFunction> funcs = new ArrayList<>();
        funcs.add(new ClaimsSourceGetter());
        funcs.add(new CreateSourceConfig());
        funcs.add(new NewTemplate());
        funcs.add(new IsInGroup());
        funcs.add(new IsInGroup2());
        funcs.add(new ScopeTemplateQDLUtil());
        funcs.add(new TemplateSubsitutionQDLUtil());
        oa2Module.addFunctions(funcs);
        if (state != null) {
            oa2Module.init(state);
        }
        setupModule(oa2Module);
        return oa2Module;
    }
        List<String> descr = new ArrayList<>();
    @Override
    public List<String> getDescription() {
        if(descr.isEmpty()){
            descr.add("This modules contains several utilities written specifically for OA4MP for processing claims");
            descr.add("It allows for creating claims sources using templates, checking group memberships");
            descr.add("and computing scopes");
        }
        return descr;
    }

}
