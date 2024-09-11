package org.oa4mp.delegation.server.jwt;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import java.net.URI;

/**
 * If there is a user-created exception thrown by the {@link edu.uiuc.ncsa.security.util.scripting.ScriptRuntimeEngine}
 * this will be thrown. This allows for propagating error conditions inside of scripts outside whatever the runtime
 * is.
 * <p>Created by Jeff Gaynor<br>
 * on 10/9/20 at  8:43 AM
 */
public class ScriptRuntimeException extends GeneralException {
    public ScriptRuntimeException() {
    }

    public ScriptRuntimeException(Throwable cause) {
        super(cause);
    }

    public ScriptRuntimeException(String message) {
        super(message);
    }

    public ScriptRuntimeException(String message, Throwable cause) {
        super(message, cause);
    }

    public String getRequestedType() {
        return requestedType;
    }

    public void setRequestedType(String requestedType) {
        this.requestedType = requestedType;
    }

    String requestedType;

    public int getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    int httpStatus;

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public static int DEFAULT_NO_OP_CODE = -1;
    int code = DEFAULT_NO_OP_CODE;

    /**
     * An error URI if one is needed. (Optional!)
     * @return
     */

    public URI getErrorURI() {
        return errorURI;
    }

    public void setErrorURI(URI errorURI) {
        this.errorURI = errorURI;
    }

    URI errorURI = null;

    public URI getCustomErrorURI() {
        return customErrorURI;
    }

    public void setCustomErrorURI(URI customErrorURI) {
        this.customErrorURI = customErrorURI;
    }

    URI customErrorURI = null;

    @Override
    public String toString() {
        return "ScriptRuntimeException{" +
                "requestedType='" + requestedType + '\'' +
                ", httpStatus=" + httpStatus +
                ", code=" + code +
                ", errorURI=" + errorURI +
                ", customErrorURI=" + customErrorURI +
                '}';
    }
}
