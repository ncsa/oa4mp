package edu.uiuc.ncsa.oa4mp.delegation.server;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * A wrapper around an exception that includes any client active at the time. This
 * is used by the exception interception machinery for consumption by the
 * error servlet.
 * <p>Created by Jeff Gaynor<br>
 * on 9/5/12 at  11:37 AM
 */
public class ExceptionWrapper extends GeneralException {
    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    Client client;


    public ExceptionWrapper(Throwable cause, Client client) {
        super(cause);
        this.client = client;
    }

}
