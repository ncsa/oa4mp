package org.oa4mp.delegation.common.servlet;

import org.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import edu.uiuc.ncsa.security.storage.XMLMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * Used by the delegation servlet, this allows a programmer to intercept and process the HTTP
 * request and response. The {@link #getParameters()} call returns the parsed parameters from
 * the request. The {@link #getTransaction()} returns the current transaction (which will
 * probably have to be cast to an appropriate subclass of {@link BasicTransaction} to be useful.
 * Save any changes to the transaction you make. Generally avoid touching the response's
 * output stream.
 * <p>Created by Jeff Gaynor<br>
 * on 4/23/12 at  4:56 PM
 */
public class TransactionState {
    public TransactionState(HttpServletRequest request,
                            HttpServletResponse response,
                            Map<String, String> parameters,
                            BasicTransaction transaction,
                            XMLMap backup) {
        this.request = request;
        this.response = response;
        this.parameters = parameters;
        this.transaction = transaction;
        this.backup = backup;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public HttpServletResponse getResponse() {
        return response;
    }

    public Map<String, String> getParameters() {
        return parameters;
    }

    public BasicTransaction getTransaction() {
        return transaction;
    }

    protected HttpServletRequest request;
    protected HttpServletResponse response;
    protected BasicTransaction transaction;
    protected Map<String, String> parameters;

    public boolean isRfc8628() {
        return rfc8628;
    }

    public void setRfc8628(boolean rfc8628) {
        this.rfc8628 = rfc8628;
    }

    boolean rfc8628 = false;

    /**
     * Backup of the original transaction before any checks are done. This may be null.
     * This allows returning the state of the transaction to whatever was there before
     * the user tried and is intended for allowing a graceful recovery from system
     * errors. It should never be the case that a user's tokens are invalidated because
     * of an internal error (e.g their LDAP server is down). Given them a change to fix it
     * and try again.
     * @return
     */
    // CIL-1268
    public XMLMap getBackup() {
        return backup;
    }

    public void setBackup(XMLMap backup) {
        this.backup = backup;
    }

    protected XMLMap backup;
}
