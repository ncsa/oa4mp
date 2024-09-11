package org.oa4mp.delegation.server.jwt;

import net.sf.json.JSONObject;

/**
 * Marker interface for handlers that have user meta data.
 * <p>Created by Jeff Gaynor<br>
 * on 1/19/21 at  8:25 AM
 */
public interface IDTokenHandlerInterface {
    JSONObject getUserMetaData();
    void setUserMetaData(JSONObject udm);
}
