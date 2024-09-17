package org.oa4mp.server.loader.qdl.claims;


import org.qdl_lang.extensions.JavaModule;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.module.Module;
import org.qdl_lang.state.State;

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
    public static final String NAMESPACE ="oa4mp:/qdl/oidc/claims";
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
