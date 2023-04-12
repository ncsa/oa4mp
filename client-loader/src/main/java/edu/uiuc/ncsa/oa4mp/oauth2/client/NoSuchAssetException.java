package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/14 at  3:48 PM
 */
public class NoSuchAssetException extends GeneralException {
    public NoSuchAssetException() {
    }

    public NoSuchAssetException(Throwable cause) {
        super(cause);
    }

    public NoSuchAssetException(String message) {
        super(message);
    }

    public NoSuchAssetException(String message, Throwable cause) {
        super(message, cause);
    }
}
