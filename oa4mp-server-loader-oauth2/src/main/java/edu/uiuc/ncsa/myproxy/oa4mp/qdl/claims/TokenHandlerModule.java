package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/20 at  6:21 AM
 */
public class TokenHandlerModule extends JavaModule {
    public TokenHandlerModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    public TokenHandlerModule() {
    }

    @Override
    public Module newInstance(State state) {
        TokenHandlerModule thm = new TokenHandlerModule(URI.create("oa2:/qdl/oidc/token"), "tokens");
        ArrayList<QDLFunction> funcs = new ArrayList<>();
        IDTokenInitializer ida = new IDTokenInitializer();
        funcs.add(ida.new idInit());
        funcs.add(ida.new idFinish());
        funcs.add(ida.new idCheckClaims());
        funcs.add(ida.new idRefresh());

        AccessTokenInitializer ai = new AccessTokenInitializer();
        funcs.add(ai.new atInit());
        funcs.add(ai.new atFinish());
        funcs.add(ai.new atRefresh());

        RefreshTokenInitializer rt = new RefreshTokenInitializer();
        funcs.add(rt.new rtInit());
        funcs.add(rt.new rtFinish());
        funcs.add(rt.new rtRefresh());


        thm.addFunctions(funcs);
        if (state != null) {
            thm.init(state);
        }
        return thm;
    }
}
