package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;

import java.net.URI;

/**
 * A standard OIDC error, where there is a valid redirect and the return codes are turned into parameters in the
 * redirect. In cases where there is no redirect available, you must use an {@link OA2GeneralError}
 * instead.
 * <h3>Note</h3>
 * This is typically used in the authorization leg of the code flow. For the token leg
 * use {@link OA2ATException} instead.
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/15 at  11:33 AM
 */
public class OA2RedirectableError extends OA2GeneralError {
    URI callback;

    public URI getCallback() {
        return callback;
    }

    public void setCallback(URI callback) {
        this.callback = callback;
    }

    public OA2RedirectableError(String error,
                                String description,
                                int httpStatus,
                                String state,
                                URI callback) {
        this(error, description, httpStatus, state);
        this.callback = callback;
    }

    public OA2RedirectableError(String error,
                                   String description,
                                   int httpStatus,
                                   String state,
                                   URI callback,
                                BaseClient client) {
           this(error, description, httpStatus, state, callback);
       }

    public OA2RedirectableError(String error, String description, int httpStatus, String state) {
        super("error: "+error+" (description: "+description+")");
        this.error = error;
        this.description = description;
        this.state = state;
        this.httpStatus = httpStatus;
    }

    public OA2RedirectableError(String error, String description, int httpStatus, String state, BaseClient client) {
        this(error,description,httpStatus,state);
        this.client=client;

    }


    public OA2RedirectableError() {
    }

    public OA2RedirectableError(Throwable cause) {
        super(cause);
    }

    public OA2RedirectableError(String message) {
        super(message);
    }

    public OA2RedirectableError(String message, Throwable cause) {
        super(message, cause);
    }

    public boolean hasCallback(){
        return callback != null;
    }

    @Override
    public String toString() {
        return "OA2RedirectableError{" +
                "httpStatus=" + httpStatus +
                ", error='" + error + '\'' +
                ", description='" + description + '\'' +
                ", state='" + state + '\'' +
                ", callback=" + callback +
                '}';
    }
}
