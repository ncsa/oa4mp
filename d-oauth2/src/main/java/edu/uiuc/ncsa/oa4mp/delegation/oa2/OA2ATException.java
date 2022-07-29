package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import org.apache.http.HttpStatus;

/**
 * This is thrown by the AT servlet and is used to construct the response which
 * must include JSON.  Mostly we need this for the type to make sure it can
 * be identified and handled properly. Note the error from the token endpoint
 * is never a redirect to the client's error endpoint, but the response is always
 * a JSON object. The  default status code for all of these is 400, bad request,
 * unless the spec. states otherwise.
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
        this(error,description,null);
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

    @Override
    public String toString() {
        return "OA2ATException{" +
                "httpStatus=" + httpStatus +
                ", error='" + error + '\'' +
                ", description='" + description + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
}
