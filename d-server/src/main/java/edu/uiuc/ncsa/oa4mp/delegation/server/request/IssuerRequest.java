package edu.uiuc.ncsa.oa4mp.delegation.server.request;

import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Request;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;

import javax.servlet.http.HttpServletRequest;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  11:57:57 AM
 */
public abstract class IssuerRequest implements Request {
    public static final int AG_TYPE = 1;
    public static final int AT_TYPE = 2;
    public static final int CB_TYPE = 3;
    public static final int PA_TYPE = 4;
    public static final int RT_TYPE = 5;
    public static final int UI_TYPE = 6;

    public abstract int getType();
    public IssuerRequest(ServiceTransaction transaction) {
        this.transaction = transaction;
    }

    public ServiceTransaction getTransaction() {
        return transaction;
    }

    /**
     * Generally this should not be needed. If possible, always set the transaction in the constructor.
     * @param transaction
     */
    public void setTransaction(ServiceTransaction transaction) {
        this.transaction = transaction;
    }

    ServiceTransaction transaction;
    public IssuerRequest(HttpServletRequest servletRequest, ServiceTransaction transaction) {
        this(transaction);
        this.servletRequest = servletRequest;
    }

    public Response process(Server server) {
        throw new NotImplementedException();
    }

    public HttpServletRequest getServletRequest() {
        return servletRequest;
    }

    public void setServletRequest(HttpServletRequest servletRequest) {
        this.servletRequest = servletRequest;
    }


    HttpServletRequest servletRequest;

    public Client getClient() {
        return getTransaction().getClient();
    }


}
