package org.oa4mp.server.loader.oauth2.functor.claims;

import edu.uiuc.ncsa.security.util.functor.JFunctorImpl;

import java.util.Collection;

/**
 * Check if a single scope is allowed for this source.
 * <p>Created by Jeff Gaynor<br>
 * on 7/23/18 at  4:41 PM
 */
public class jhasScope extends JFunctorImpl {
    public jhasScope(Collection<String> scopes) {
        super(FunctorClaimsType.HAS_SCOPE);
        this.scopes = scopes;
    }

    Collection<String> scopes;

    @Override
    public Object execute() {
        if (isExecuted()) {
            return result;
        }
        if (getArgs().size() < 1) {
            throw new IllegalArgumentException("Error: No scope specified");
        }
        result = scopes.contains(getArgs().get(0));
        executed = true;
        return result;
    }
}
