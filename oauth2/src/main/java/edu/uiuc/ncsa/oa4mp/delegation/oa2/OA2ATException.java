package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import org.apache.http.HttpStatus;

import java.net.URI;

/**
 * This is thrown by the AT servlet and is used to construct the response which
 * must include JSON.  Mostly we need this for the type to make sure it can
 * be identified and handled properly. Note the error from the token endpoint
 * is never a redirect to the client's error endpoint, but the response is always
 * a JSON object. The  default status code for all of these is 400, bad request,
 * unless the spec. states otherwise.
 * <p>The {@link #errorURI}</p> will be returned in the body of the response
 * as per <a href="https://www.rfc-editor.org/rfc/rfc6749#section-4.2.2.1">OAuth2 error</a>.
 * <p>Created by Jeff Gaynor<br>
 * on 9/14/16 at  12:26 PM
 */
// This class is part of the fix for CIL-332.
public class OA2ATException extends OA2GeneralError {

    public OA2ATException(OA2RedirectableError error) {
        super(error);
    }

    /**
     * Case for very early failure, e.g., invalid client id. No way to get the callback, state, etc.
     * @param error
     * @param description
     */
    public OA2ATException(String error, String description) {
        this(error,description,(String)null);
    }
    public OA2ATException(String error, String description, BaseClient client) {
        this(error, description);
        this.client = client;
    }

    /**
     * The vast majority of error from the token endpoint are required by the RFC (section 5.2)
     * to return a bad request (400) http status.
     * @param error
     * @param description
     * @param state
     */
    public OA2ATException(String error, String description,  String state) {
        super(error, description, HttpStatus.SC_BAD_REQUEST, state);
    }
    public OA2ATException(String error, String description,  String state, BaseClient client) {
        super(error, description, HttpStatus.SC_BAD_REQUEST, state, client);
    }

    /**
     * Most general exception if something more exotic than error + description + bad request is needed.
     * @param error
     * @param description
     * @param httpStatus
     * @param state
     */
    public OA2ATException(String error, String description, int httpStatus, String state) {
        super(error, description, httpStatus, state);
    }
    public OA2ATException(String error, String description, int httpStatus, String state, BaseClient client) {
       this(error, description, httpStatus, state);
       this.client = client;
    }

    public OA2ATException(String error, String description, int httpStatus, URI errorURI, String state) {
         super(error, description, httpStatus, state);
         this.errorURI = errorURI;
     }
    public OA2ATException(String error, String description, int httpStatus, URI errorURI, String state, BaseClient client) {
       this(error, description, httpStatus, errorURI, state);
       this.client = client;
    }

    @Override
    public String toString() {
        return "OA2ATException{" +
                "httpStatus=" + httpStatus +
                ", error='" + error + '\'' +
                ", description='" + description + '\'' +
                ", errorURI='" + errorURI + "\'" +
                ", state='" + state + '\'' +
                ", client='" + (hasClient()?"(none)":getClient().getIdentifierString()) + '\'' +
                '}';
    }

    public URI getErrorURI() {
        return errorURI;
    }

    public void setErrorURI(URI errorURI) {
        this.errorURI = errorURI;
    }

    URI errorURI;
}
