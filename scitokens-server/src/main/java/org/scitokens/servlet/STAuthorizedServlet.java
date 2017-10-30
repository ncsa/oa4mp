package org.scitokens.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2AuthorizedServlet;
import org.scitokens.util.STTransaction;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RedirectableError;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;

import java.util.ArrayList;
import java.util.Map;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.SCOPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  3:22 PM
 */
public class STAuthorizedServlet extends OA2AuthorizedServlet {
    @Override
    protected ArrayList<String> resolveScopes(OA2ServiceTransaction st, Map<String, String> params, String state, String givenRedirect) {
        STTransaction stTransaction = (STTransaction) st;
        String scopeCaput = "demo:";

        String rawScopes = params.get(SCOPE);
        if (rawScopes == null || rawScopes.length() == 0) {
            throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE, "Missing scopes parameter.", state, givenRedirect);
        }

        StringTokenizer stringTokenizer = new StringTokenizer(rawScopes);
        ArrayList<String> scopes = new ArrayList<>();
        boolean hasOpenIDScope = false;
        String stScopes = "";
        while (stringTokenizer.hasMoreTokens()) {
            String x = stringTokenizer.nextToken();
            if (!OA2Scopes.ScopeUtil.hasScope(x)) {
                //  throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE, "Unrecognized scope \"" + x + "\"", state, givenRedirect);
                if (x.startsWith(scopeCaput)) {
                    stScopes = stScopes + " " + x;
                }
            }
            if (x.equals(OA2Scopes.SCOPE_OPENID)) hasOpenIDScope = true;
            scopes.add(x);
        }


        if (!hasOpenIDScope)
            throw new OA2RedirectableError(OA2Errors.INVALID_REQUEST, "Scopes must contain openid", state, givenRedirect);
        stTransaction.setStScopes(stScopes);
        return scopes;
    }

    @Override
    protected OA2ServiceTransaction createNewTransaction(AuthorizationGrant grant) {
        return new STTransaction(grant);
    }
}
