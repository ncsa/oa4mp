package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.ArrayList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/20 at  1:24 PM
 */
public class JWTModule extends JavaModule {
    public JWTModule() {
    }

    public JWTModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        JWTModule jwtModule = new JWTModule(URI.create("oa2:/qdl/jwt"), "jwt");
        JWTCommands jwtCommands = new JWTCommands(null);
        if (state != null) {
            jwtCommands.setLogger(state.getLogger());
        }
        funcs = new ArrayList<>();
        funcs.add(jwtCommands.new CreateJWK());
        funcs.add(jwtCommands.new LoadJWK());
        funcs.add(jwtCommands.new KeyInfo());
        funcs.add(jwtCommands.new SaveKeys());
        funcs.add(jwtCommands.new CreateJWT());
        funcs.add(jwtCommands.new VerifyJWT());
        funcs.add(jwtCommands.new GetHeader());
        funcs.add(jwtCommands.new GetPayload());
        funcs.add(jwtCommands.new DefaultKey());
        funcs.add(jwtCommands.new SymmKeys());
        jwtModule.addFunctions(funcs);
        vars = new ArrayList<>();
        vars.add(jwtCommands.new TestClaims());
        vars.add(jwtCommands.new TestScopes());
        vars.add(jwtCommands.new TestAudience());
        vars.add(jwtCommands.new TestXAs());
        jwtModule.addVariables(vars);
        if (state != null) {
            jwtModule.init(state);
        }
        return jwtModule;
    }
}
