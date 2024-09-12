package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.server.UnsupportedScopeException;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;

/**
 * <p>This is to test creating claim sources using the introspection abilities of OA4MP.
 * It has to live in this package (rather than in some test harness) because part of the
 * contract is that it is resolvable at runtime and test code is not available.
 * </p>
 * <p>
 * Generally, this does virtually nothing except spit out a few dummy claims. It is therefore
 * of no use  and can be safely ignored. It's function is to be an example of how to write a
 * custom claim source.
 * </p>
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/20 at  8:30 AM
 */
public class TestClaimSource extends BasicClaimsSourceImpl {
    public TestClaimSource() {
    }

    @Override
    protected JSONObject realProcessing(JSONObject claims,
                                        HttpServletRequest request,  
                                        ServiceTransaction transaction) throws UnsupportedScopeException {
        claims.put("info", "Echoing configuration parameters.");
        claims.put("username", transaction.getUsername());
        for (String key : configuration.getProperties().keySet()) {
            claims.put(key, configuration.getProperties().get(key));
        }
        return claims;
    }

}
