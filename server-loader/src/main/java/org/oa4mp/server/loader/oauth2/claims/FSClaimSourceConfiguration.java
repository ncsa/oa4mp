package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/25/24 at  6:29 AM
 */
public class FSClaimSourceConfiguration extends ClaimSourceConfiguration {
    public JSONObject getJson() {
        return json;
    }

    public void setJson(JSONObject json) {
        this.json = json;
    }

    JSONObject json = null;
    public boolean hasJSON(){
        return json != null;
    }
}
