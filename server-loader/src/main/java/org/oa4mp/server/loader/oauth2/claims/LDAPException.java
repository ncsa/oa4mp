package org.oa4mp.server.loader.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/22/22 at  4:31 PM
 */
public class LDAPException extends GeneralException {
    public LDAPException() {
    }

    public LDAPException(Throwable cause) {
        super(cause);
    }

    public LDAPException(String message) {
        super(message);
    }

    public LDAPException(String message, Throwable cause) {
        super(message, cause);
    }
}
