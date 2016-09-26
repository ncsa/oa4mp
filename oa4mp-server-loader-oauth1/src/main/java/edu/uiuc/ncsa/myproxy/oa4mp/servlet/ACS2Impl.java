package edu.uiuc.ncsa.myproxy.oa4mp.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.ACS2;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static edu.uiuc.ncsa.security.core.util.DateUtils.checkTimestamp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  1:29 PM
 */
public class ACS2Impl extends ACS2 {
    @Override
    protected AccessToken getAccessToken(HttpServletRequest request) {
        return getServiceEnvironment().getTokenForge().getAccessToken(request);

    }

    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        PAResponse par = (PAResponse) iResponse;
        AccessToken accessToken = par.getAccessToken();
        ServiceTransaction t = (ServiceTransaction) getTransactionStore().get(accessToken);

        if (t == null) {
            throw new GeneralException("Error: no transaction found for access token \"" + accessToken + "\"");
        }

        if (!t.isAccessTokenValid()) {
            throw new GeneralException("Error: invalid access token. Request refused");
        }
        checkClient(t.getClient());
        checkTimestamp(accessToken.getToken());
        return t;
    }

    @Override
    protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable {
        // nothing to do here in this protocol.
    }
}
