package org.oa4mp.delegation.server.server.config;

import org.oa4mp.delegation.server.server.claims.ClaimSourceConfiguration;
import net.sf.json.JSONObject;

/**
 * All components that are configurations should probably
 * extend this. That means that there is a JSON object behind the
 * scenes that is used for all attributes and all the implementation does is front that.
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/18 at  2:12 PM
 */
public abstract class JSONClaimSourceConfig extends ClaimSourceConfiguration {
    public JSONClaimSourceConfig(JSONObject jsonObject) {
        this.jsonObject = jsonObject;
    }

    protected JSONObject jsonObject;

    public boolean hasJSONObject() {
        return jsonObject != null;
    }

    public JSONObject toJSON() {
        if (jsonObject == null) {
            return new JSONObject();

        }
        return jsonObject;
    }

    public void fromJSON(JSONObject json) {
        this.jsonObject = json;
    }

}
