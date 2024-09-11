package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.delegation.server.jwt.PayloadHandlerConfig;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import javax.servlet.http.HttpServletRequest;

/**
 * The configuration for the payload handler (id token, various access tokens). This is the state
 * the handler needs to operate (current transaction, environment) as opposed to the functionality
 * for making tokens (in {@link }
 * <p>Created by Jeff Gaynor<br>
 * on 6/30/20 at  10:53 AM
 */
public class PayloadHandlerConfigImpl implements PayloadHandlerConfig {
    OA2SE oa2se;
    OA2ServiceTransaction transaction;
    HttpServletRequest request;

    public AbstractPayloadConfig getPayloadConfig() {
        return clientConfig;
    }

    public void setClientConfig(AbstractPayloadConfig clientConfig) {
        this.clientConfig = clientConfig;
    }

    public AbstractPayloadConfig getClientConfig() {
        return clientConfig;
    }

    AbstractPayloadConfig clientConfig;
     public boolean hasTXRecord(){
         return txRecord != null;
     }
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
                                    OA2Client cLient,
                                    TXRecord txRecord,
                                    HttpServletRequest request) {
        clientConfig = abstractClientConfig;
        this.oa2se = oa2se;
        this.transaction = transaction;
        this.request = request;
        this.txRecord = txRecord;
        this.client = cLient;
    }

    /**
     * Get the client associated with this. <b>NOTE</b> that this client is possibly resolved
     * from prototypes and is therefore not the client in the transaction. It is needed to
     * set the correct lifetimes and such later.
     * @return
     */
    public OA2Client getClient() {
        return client;
    }

    public void setClient(OA2Client client) {
        this.client = client;
    }

    OA2Client client;

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

    @Override
    public String toString() {
        return "PayloadHandlerConfigImpl{" +
                "oa2se=" + oa2se +
                ", transaction=" + transaction +
                ", request=" + request +
                ", clientConfig=" + clientConfig +
                ", txRecord=" + txRecord +
                '}';
    }

    boolean legacyHandler = false;

    public boolean isLegacyHandler() {
        return legacyHandler;
    }

    public void setLegacyHandler(boolean b) {
        legacyHandler = b;
    }
}
