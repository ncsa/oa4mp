package org.oa4mp.myproxy.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import org.oa4mp.delegation.common.servlet.TransactionState;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.server.issuers.PAIssuer;
import org.oa4mp.delegation.server.request.PARequest;
import org.oa4mp.delegation.server.request.PAResponse;
import org.oa4mp.server.api.ServiceConstantKeys;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Cert servlet, version 2.
 * <p>Created by Jeff Gaynor<br>
 * on 2/7/14 at  1:22 PM
 */
public abstract class ACS2 extends MyProxyServlet {
    protected PAIssuer getPAI() throws IOException {
        return getServiceEnvironment().getPaIssuer();
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        doDelegation(httpServletRequest, httpServletResponse);
    }


    protected void doDelegation(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        info("6.a. Starting to process cert request");
        AccessToken accessToken = getAccessToken(httpServletRequest);
        ServiceTransaction serviceTransaction = (ServiceTransaction) getTransactionStore().get(accessToken);

        XMLMap backup = GenericStoreUtils.toXML(getTransactionStore(), serviceTransaction);
        PARequest paRequest = new PARequest(httpServletRequest, serviceTransaction);
        String statusString = "client = " + paRequest.getClient().getIdentifier();
        // The next call will pull the access token off of any parameters. The result may be null if there is
        // no access token.
        paRequest.setAccessToken(accessToken);

        PAResponse paResponse = (PAResponse) getPAI().process(paRequest);
        debug("6.a. " + statusString);
        ServiceTransaction t = verifyAndGet(paResponse);
        Map params = httpServletRequest.getParameterMap();

        if (t.getCertReq() == null) {
            //CIL-409 fix -- fail immediately if the cert request is missing
            if(!params.containsKey(CONST(ServiceConstantKeys.CERT_REQUEST_KEY))){
                throw new GeneralException("Error: Missing cert request parameter.");
            }
            String rawCR = ((String[]) params.get(CONST(ServiceConstantKeys.CERT_REQUEST_KEY)))[0];
            // CIL-409 fix
            if(isEmpty(rawCR)){
                throw new GeneralException("Error: Empty cert request.");
            }
            MyPKCS10CertRequest certReq;
            try {
                certReq = CertUtil.fromStringToCertReq(rawCR);
            } catch (Throwable throwable) {
                if(DebugUtil.isEnabled()) {
                    throwable.printStackTrace();
                }
                GenericStoreUtils.fromXMLAndSave(getTransactionStore(), backup); // back out of it, let them try again later
                throw new GeneralException("Error: cert request is bad/not understandable:" + (rawCR == null ? "(null)" : rawCR), throwable);
            }
            t.setCertReq(certReq);
            // The assumption at this point is that this value is in seconds, which is valid for OIDC clients.
            if(params.containsKey(CONST(ServiceConstantKeys.CERT_LIFETIME_KEY))) {
                t.setLifetime(1000 * Long.parseLong(((String[]) params.get(CONST(ServiceConstantKeys.CERT_LIFETIME_KEY)))[0]));
            }else{
                t.setLifetime(1000*10*24*3600); // set the default to 10 days if there is no certlifetime parameter passed in.
            }
            getTransactionStore().save(t);
        }


        info("6.a. Processing request for transaction " + t.getIdentifier());
        doRealCertRequest(t, statusString);
        t.setAccessTokenValid(false);
        preprocess(new TransactionState(httpServletRequest, httpServletResponse, paResponse.getParameters(), t, backup));

        debug("6.a. protected asset:" + (t.getProtectedAsset() == null ? "(null)" : "ok") + ", " + statusString);
        HashMap<String, String> username = new HashMap<String, String>();
        username.put("username", t.getUsername());
        if (paResponse.getParameters() != null) {
            username.putAll(paResponse.getParameters());
        }
        paResponse.setAdditionalInformation(username);
        paResponse.setProtectedAsset(t.getProtectedAsset());
        debug("6.a. Added username \"" + t.getUsername() + "\" & cert for request from " + statusString);
        getTransactionStore().save(t);

        info("6.b. Done with cert request " + statusString);
        paResponse.write(httpServletResponse);
        info("6.b. Completed transaction " + t.getIdentifierString() + ", " + statusString);
        postprocess(new TransactionState(httpServletRequest, httpServletResponse, paResponse.getParameters(), t, backup));
    }

}
