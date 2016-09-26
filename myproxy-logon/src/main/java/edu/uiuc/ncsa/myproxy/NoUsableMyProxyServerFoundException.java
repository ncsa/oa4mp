package edu.uiuc.ncsa.myproxy;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/1/15 at  10:23 AM
 */
public class NoUsableMyProxyServerFoundException extends GeneralException {
    public NoUsableMyProxyServerFoundException() {
    }

    public NoUsableMyProxyServerFoundException(Throwable cause) {
        super(cause);
    }

    public NoUsableMyProxyServerFoundException(String message) {
        super(message);
    }

    public NoUsableMyProxyServerFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
