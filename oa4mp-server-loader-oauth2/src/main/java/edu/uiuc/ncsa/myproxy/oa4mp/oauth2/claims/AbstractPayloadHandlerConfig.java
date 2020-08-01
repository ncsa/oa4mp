package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import javax.servlet.http.HttpServletRequest;

/**
 * Marker interface
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  10:53 AM
 */
public abstract class AbstractPayloadHandlerConfig implements PayloadHandlerConfig {
    OA2SE oa2se;
    OA2ServiceTransaction transaction;
    HttpServletRequest request;

    public AbstractClientConfig getClientConfig() {
        return clientConfig;
    }

    public void setClientConfig(AbstractClientConfig clientConfig) {
        this.clientConfig = clientConfig;
    }

    AbstractClientConfig clientConfig;

    public AbstractPayloadHandlerConfig(AbstractClientConfig abstractClientConfig,
                                        OA2SE oa2se,
                                        OA2ServiceTransaction transaction,
                                        HttpServletRequest request) {
        clientConfig = abstractClientConfig;
        this.oa2se = oa2se;
        this.transaction = transaction;
        this.request = request;
    }


    public OA2SE getOa2se() {
        return oa2se;
    }

    public void setOa2se(OA2SE oa2se) {
        this.oa2se = oa2se;
    }

    public OA2ServiceTransaction getTransaction() {
        return transaction;
    }

    public void setTransaction(OA2ServiceTransaction transaction) {
        this.transaction = transaction;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }


    @Override
    public ScriptSet getScriptSet() {
        return clientConfig.getScriptSet();
    }

}
