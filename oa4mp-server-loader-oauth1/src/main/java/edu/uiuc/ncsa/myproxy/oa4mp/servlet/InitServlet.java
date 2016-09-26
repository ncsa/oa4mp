package edu.uiuc.ncsa.myproxy.oa4mp.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractInitServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.request.AGResponse;
import edu.uiuc.ncsa.security.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

import java.io.IOException;
import java.net.URI;
import java.util.Map;

import static edu.uiuc.ncsa.security.oauth_1_0a.OAuthConstants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 17, 2011 at  3:38:58 PM
 */
public class InitServlet extends AbstractInitServlet {
    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        AGResponse agResponse = (AGResponse) iResponse;
        Map<String, String> params = agResponse.getParameters();
        ServiceTransaction transaction = newTransaction();
        transaction.setAuthorizationGrant(agResponse.getGrant());
        debug("creating transaction for trans id=" + transaction.getIdentifierString());

        transaction.setAuthGrantValid(false);
        transaction.setAccessTokenValid(false);
        transaction.setCallback(URI.create(params.get(OAUTH_CALLBACK)));
        MyPKCS10CertRequest certReq = null;
        String rawCR = params.get(CERT_REQUEST);
        try {
            certReq = CertUtil.fromStringToCertReq(rawCR);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
            throw new GeneralException("Error: cert request is bad/not understandable:" + (rawCR==null?"(null)":rawCR), throwable);
        }
        transaction.setCertReq(certReq);
        // Assumption here is that the cert lifetime is in milliseconds
        transaction.setLifetime(Long.parseLong(params.get(CERT_LIFETIME)));
        return transaction;
    }


}
