package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import net.sf.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;

/**
 * This is for the specific case that claims are passed through the headers. Each starts with the caput
 * and every claim with this caput is processed and added. E.g.
 * <pre>
 *     OIDC_CLAIM_sub
 * </pre>
 * sets the "sub" claim.
 * <p>Created by Jeff Gaynor<br>
 * on 3/15/17 at  2:41 PM
 */
public class HTTPHeaderClaimsSource extends BasicClaimsSourceImpl {
    public HTTPHeaderClaimsSource(ClaimSourceConfiguration configuration) {
        setConfiguration(configuration);
    }

    public String caput = "OIDC_CLAIM_";

    public String getCaput() {
        return caput;
    }

    public void setCaput(String caput) {
        this.caput = caput;
    }


    @Override
    protected JSONObject realProcessing(JSONObject claims, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        DebugUtil.trace(this,"Omit list = " + getOmitList());
        Enumeration headerNames = request.getHeaderNames();
        String caput = getCaput();
        if (caput == null) {
            caput = ""; // default is empty caput.
        }
        int caputLength = caput.length();
        while (headerNames.hasMoreElements()) {
            String name = headerNames.nextElement().toString();
            DebugUtil.dbg(this, "processing claim " + name);
            /*
            The resulting claim is without the caput, so if the caput is "OIDC_CLAIM_" and the header has a field named "OIDC_CLAIM_idp"
            the resulting claim would be called "idp"
             */
            if (name.startsWith(caput)) {
                String key = name.substring(caputLength);
                String value = request.getHeader(name);
                if (!getOmitList().contains(key)) {
                    DebugUtil.dbg(this, "adding claim " + key + "=" + value);
                    claims.put(key, value);
                }else{
                    DebugUtil.dbg(this, "OMITTING claim " + key + "=" + value + ", as per omit list");
                }
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
