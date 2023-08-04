package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import net.sf.json.JSONObject;

/**
 * Used for exceptions that must be returned as JSON.
 * <p>Created by Jeff Gaynor<br>
 * on 8/3/23 at  4:06 PM
 */
public class OA2JSONException extends OA2GeneralError{
    public OA2JSONException(OA2RedirectableError error) {
        super(error);
    }

    public OA2JSONException(Throwable cause) {
        super(cause);
    }

    public OA2JSONException() {
    }

    public OA2JSONException(String message) {
        super(message);
    }

    public OA2JSONException(String message, Throwable cause) {
        super(message, cause);
    }

    public OA2JSONException(String error, String description, int httpStatus, String state) {
        super(error, description, httpStatus, state);
    }

    public OA2JSONException(String error, String description, int httpStatus, String state, BaseClient client) {
        super(error, description, httpStatus, state, client);
    }
    public boolean asJSON(){
        return true;
    }
    public JSONObject toJSON(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put(OA2Constants.ERROR, getError());
        jsonObject.put(OA2Constants.ERROR_DESCRIPTION, getDescription());
        if (getState() != null) {
            // not quite the spec., but clients may need this.
            jsonObject.put(OA2Constants.STATE, getState());        }
        return jsonObject;
    }
}
