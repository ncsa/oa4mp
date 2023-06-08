package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * This is for use places where there is no redirect url available. Examples are the userInfo and getCert endpoints for OA4MP.
 * It has an error and description but will be turned into a standard
 * response with the given status code. It is up to any client to interpret this correctly.
 * <p>Created by Jeff Gaynor<br>
 * on 10/22/15 at  11:18 AM
 */
public class OA2GeneralError extends GeneralException {

    /**
     * Convert a redirectable error to a general one. The default is to set the status code
     * to 400 = bad request so something is there.
     *
     * @param error
     */
    public OA2GeneralError(OA2RedirectableError error) {
        super("error: " + error.getError()
                + " (status: " + error.getHttpStatus()
                + ", description: "
                + error.getDescription()
                + (error.getState() == null ? "" : ", state:" + error.getState())
                + ")");

        setDescription(error.getDescription());
        setError(error.getError());
        setHttpStatus(error.getHttpStatus());
        setState(error.getState());
        setClient(error.getClient());
    }

    public boolean hasClient() {
        return client != null;
    }

    public BaseClient getClient() {
        return client;
    }

    public void setClient(BaseClient client) {
        this.client = client;
    }

    protected BaseClient client;

    public OA2GeneralError(Throwable cause) {
        super(cause);
    }

    public OA2GeneralError() {

    }

    public OA2GeneralError(String message) {
        super(message);
    }

    public OA2GeneralError(String message, Throwable cause) {
        super(message, cause);
    }

    public OA2GeneralError(String error,
                           String description,
                           int httpStatus,
                           String state) {
        super("error: " + error + " (status: " + httpStatus + ", description: " + description + (state == null ? "" : ", state:" + state) + ")");
        setValues(error, description, httpStatus, state);
    }

    public OA2GeneralError(String error,
                           String description,
                           int httpStatus,
                           String state,
                           BaseClient client) {
        this(error, description, httpStatus, state);
        this.client = client;

    }

    public void setValues(String error, String description, int httpStatus, String state) {
        this.description = description;
        this.error = error;
        this.httpStatus = httpStatus;
        this.state = state;
    }


    public int getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    int httpStatus;
    String error;
    String description;

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    String state;


    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }


    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public String toString() {
        return "OA2GeneralError{" +
                "httpStatus=" + httpStatus +
                ", error='" + error + '\'' +
                ", description='" + description + '\'' +
                ", state='" + state + '\'' +
                '}';
    }
}
