package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.UnsupportedScopeException;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/15/17 at  2:41 PM
 */
public class HTTPHeaderClaimsSource extends BasicClaimsSourceImpl {
    public String caput = "OIDC_CLAIM_";

    @Override
    public UserInfo process(UserInfo userInfo, HttpServletRequest request, ServiceTransaction transaction) throws UnsupportedScopeException {
        DebugUtil.dbg(this, "starting to process claims");

        Enumeration headerNames = request.getHeaderNames();
        int caputLength = caput.length();
        Map<String, Object> claims = userInfo.getMap();
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
        super.process(userInfo, request, transaction);
        return userInfo;
    }

    @Override
    public UserInfo process(UserInfo userInfo, ServiceTransaction transaction) throws UnsupportedScopeException {
        throw new NotImplementedException("A servlet request must be supplied for this handler");
    }
}
