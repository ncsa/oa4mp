package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/24/13 at  1:21 PM
 */
public class InvalidNonceException extends GeneralException {
    public InvalidNonceException() {
    }

    public InvalidNonceException(Throwable cause) {
        super(cause);
    }

    public InvalidNonceException(String message) {
        super(message);
    }

    public InvalidNonceException(String message, Throwable cause) {
        super(message, cause);
    }
}
