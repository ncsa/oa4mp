package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import net.sf.json.JSONObject;

/**
 * Thanks to Java package restrictions, have to make an interface for TXRecords here.
 * <p>Created by Jeff Gaynor<br>
 * on 10/16/23 at  9:29 AM
 */
public interface TXRecordInterface {
    String getStoredToken();

    void setStoredToken(String storedToken);

    JSONObject getToken();

    void setToken(JSONObject token);
}
