package org.oa4mp.delegation.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/1/23 at  10:09 AM
 */
public class NoSuchClientException extends GeneralException {
    public NoSuchClientException() {
    }

    public NoSuchClientException(Throwable cause) {
        super(cause);
    }

    public NoSuchClientException(String message) {
        super(message);
    }

    public NoSuchClientException(String message, Throwable cause) {
        super(message, cause);
    }
}
