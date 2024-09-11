package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/17/15 at  2:30 PM
 */
public class UnsupportedScopeException extends GeneralException {
    public UnsupportedScopeException() {
    }

    public UnsupportedScopeException(Throwable cause) {
        super(cause);
    }

    public UnsupportedScopeException(String message) {
        super(message);
    }

    public UnsupportedScopeException(String message, Throwable cause) {
        super(message, cause);
    }
}
