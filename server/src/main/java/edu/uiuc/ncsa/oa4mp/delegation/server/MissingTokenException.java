package edu.uiuc.ncsa.oa4mp.delegation.server;


import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * An exception when a token that must be present is not. Generally try to intercept missing tokens before
 * any lower level calls do that since it can be hard to untangle which token was missing where.
 * <p>Created by Jeff Gaynor<br>
 * on 9/20/11 at  12:30 PM
 */
public class MissingTokenException extends GeneralException {
    public MissingTokenException() {
    }

    public MissingTokenException(Throwable cause) {
        super(cause);
    }

    public MissingTokenException(String message) {
        super(message);
    }

    public MissingTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
