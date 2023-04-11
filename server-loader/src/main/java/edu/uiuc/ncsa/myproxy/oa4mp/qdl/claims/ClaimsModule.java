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
public class ClaimsModule extends JavaModule {
    public ClaimsModule() {
    }

    protected ClaimsModule(URI namespace, String alias) {
        super(namespace, alias);
    }
    public static final String NAMESPACE ="oa2:/qdl/oidc/claims";
    @Override
    public Module newInstance(State state) {
        ClaimsModule claimsModule = new ClaimsModule(URI.create(NAMESPACE), "claims");

        ArrayList<QDLFunction> funcs = new ArrayList<>();
        funcs.add(new ClaimsSourceGetter());
        funcs.add(new CreateSourceConfig());
        funcs.add(new NewTemplate());
        funcs.add(new IsInGroup());
        funcs.add(new IsInGroup2());
        ScopeTemplateQDLUtil qdlUtil= new ScopeTemplateQDLUtil();
        funcs.add(qdlUtil.new ResolveTemplates());
        funcs.add(qdlUtil.new Downscope());
        funcs.add(qdlUtil.new QueryScopes());
        funcs.add(qdlUtil.new ToScopeString());
        funcs.add(new TemplateSubsitutionQDLUtil());
        claimsModule.addFunctions(funcs);
        if (state != null) {
            claimsModule.init(state);
        }
        setupModule(claimsModule);
        return claimsModule;
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
