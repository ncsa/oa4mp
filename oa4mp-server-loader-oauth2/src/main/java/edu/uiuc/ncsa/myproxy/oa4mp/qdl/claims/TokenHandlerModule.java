package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

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
    public Module newInstance(State state1) {
        OA2State state = (OA2State)state1;
        TokenHandlerModule thm = new TokenHandlerModule(URI.create("oa2:/qdl/oidc/token"), "tokens");
        ArrayList<QDLFunction> funcs = new ArrayList<>();
        IDTokenInitializer ida = new IDTokenInitializer();
        funcs.add(ida.new idInit(state));
        funcs.add(ida.new idFinish(state));
        funcs.add(ida.new idCheckClaims(state));
        funcs.add(ida.new idRefresh(state));

        AccessTokenInitializer ai = new AccessTokenInitializer();
        funcs.add(ai.new atInit(state));
        funcs.add(ai.new atFinish(state));
        funcs.add(ai.new atRefresh(state));

        RefreshTokenInitializer rt = new RefreshTokenInitializer();
        funcs.add(rt.new rtInit(state));
        funcs.add(rt.new rtFinish(state));
        funcs.add(rt.new rtRefresh(state));


        thm.addFunctions(funcs);
        if (state != null) {
            thm.init(state);
        }
        setupModule(thm);
        return thm;
    }

    List<String> descr = new ArrayList<>();

    @Override
    public List<String> getDescription() {
        if (descr.isEmpty()) {
            descr.add("This module allows you to access the token handler support of OA4MP as it relates");
            descr.add("to id, access and refresh tokens. They are all done similarly in that there is");
            descr.add("an init call that sets up the handler, you set the appropriate values in the appropriate");
            descr.add("stem (e.g. "+ QDLRuntimeEngine.SRE_REQ_ACCESS_TOKEN + ".) and when you are done,");
            descr.add("call the appropirate finish command, which ensures that all required fields (like");
            descr.add("time stamps are done right.");
            descr.add("On token refresh or exchange, invoke the refresh call. It is possible that the");
            descr.add("client will require a different set of claims in the refresh. ");
        }
        return descr;
    }
}
