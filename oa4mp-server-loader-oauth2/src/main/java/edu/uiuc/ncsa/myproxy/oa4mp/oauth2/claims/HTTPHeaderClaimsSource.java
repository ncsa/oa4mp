package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/15/17 at  2:41 PM
 */
public class HTTPHeaderClaimsSource extends BasicClaimsSourceImpl {
    public String caput = "OIDC_CLAIM_";



    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        Enumeration headerNames = request.getHeaderNames();
        int caputLength = caput.length();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement().toString();
            DebugUtil.dbg(this, "processing claim " + name);

            if (name.startsWith(caput)) {
                String key = name.substring(caputLength);
                String value =request.getHeader(name);
                DebugUtil.dbg(this, "adding claim " + key + "=" + value);
                claims.put(key,value );
            }
        }
        return super.realProcessing(claims, request, transaction);
    }

    @Override
    public JSONObject process(JSONObject claims, ServiceTransaction transaction) throws UnsupportedScopeException {
        throw new NotImplementedException("A servlet request must be supplied for this handler");
    }

    @Override
    public boolean isRunAtAuthorization() {
        return true;
    }
}
