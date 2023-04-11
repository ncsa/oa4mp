package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.servlet.TransactionState;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.impl.BasicTransaction;
import edu.uiuc.ncsa.security.storage.XMLMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/13/14 at  10:42 AM
 */
public class IssuerTransactionState extends TransactionState {
    public IssuerTransactionState(HttpServletRequest request,
                                  HttpServletResponse response,
                                  Map<String, String> parameters,
                                  BasicTransaction transaction,
                                  XMLMap backup,
                                  IssuerResponse issuerResponse) {
        super(request, response, parameters, transaction, backup);
        this.issuerResponse  = issuerResponse;
    }

    IssuerResponse issuerResponse;

    public IssuerResponse getIssuerResponse() {
        return issuerResponse;
    }

    public void setIssuerResponse(IssuerResponse issuerResponse) {
        this.issuerResponse = issuerResponse;
    }

}
