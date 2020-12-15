package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import javax.servlet.http.HttpServletRequest;

/**
 * The configuration for the payload handler (id token, various access tokens). This is the state
 * the handler needs to operate (current transaction, environment) as opposed to the functionality
 * for making tokens (in {@link }
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  10:53 AM
 */
public  class PayloadHandlerConfigImpl implements PayloadHandlerConfig {
    OA2SE oa2se;
    OA2ServiceTransaction transaction;
    HttpServletRequest request;

    public AbstractPayloadConfig getPayloadConfig() {
        return clientConfig;
    }

    public void setClientConfig(AbstractPayloadConfig clientConfig) {
        this.clientConfig = clientConfig;
    }

    AbstractPayloadConfig clientConfig;

    public TXRecord getTxRecord() {
        return txRecord;
    }

    public void setTxRecord(TXRecord txRecord) {
        this.txRecord = txRecord;
    }

    TXRecord txRecord;

    public PayloadHandlerConfigImpl(AbstractPayloadConfig abstractClientConfig,
                                    OA2SE oa2se,
                                    OA2ServiceTransaction transaction,
                                    TXRecord txRecord,
                                    HttpServletRequest request) {
        clientConfig = abstractClientConfig;
        this.oa2se = oa2se;
        this.transaction = transaction;
        this.request = request;
        this.txRecord = txRecord;
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
