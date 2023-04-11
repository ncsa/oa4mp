package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/23/16 at  3:00 PM
 */
public class PermissionException extends GeneralException {
    public PermissionException() {
    }

    public PermissionException(Throwable cause) {
        super(cause);
    }

    public PermissionException(String message) {
        super(message);
    }

    public PermissionException(String message, Throwable cause) {
        super(message, cause);
    }
}
