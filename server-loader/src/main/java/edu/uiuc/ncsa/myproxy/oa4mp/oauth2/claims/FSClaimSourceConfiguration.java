package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSourceConfiguration;
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
