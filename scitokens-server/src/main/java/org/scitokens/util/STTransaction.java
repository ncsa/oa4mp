package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  8:26 AM
 */
public class STTransaction extends OA2ServiceTransaction {
    public STTransaction(AuthorizationGrant ag) {
        super(ag);
    }

    public STTransaction(Identifier identifier) {
        super(identifier);
    }

    JSONObject claims;

    public JSONObject getClaims() {
        return claims;
    }

    public void setClaims(JSONObject claims) {
        this.claims = claims;
    }

    public String getStScopes() {
        return stScopes;
    }

    public void setStScopes(String stScopes) {
        this.stScopes = stScopes;
    }

    String stScopes;
}
