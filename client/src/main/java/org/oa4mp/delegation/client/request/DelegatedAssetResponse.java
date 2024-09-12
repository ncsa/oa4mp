package org.oa4mp.delegation.client.request;


import org.oa4mp.delegation.common.token.ProtectedAsset;

import java.util.HashMap;
import java.util.Map;

/**
 * The delegated asset. The reponse may also include additional information that
 * are returned as key/value pairs in a map. These may or may not be present.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 15, 2011 at  11:13:35 AM
 */
public class DelegatedAssetResponse extends BasicResponse {
    public DelegatedAssetResponse(ProtectedAsset protectedAsset) {
        this.protectedAsset = protectedAsset;
    }

    public ProtectedAsset getProtectedAsset() {
        return protectedAsset;
    }

    public void setProtectedAsset(ProtectedAsset protectedAsset) {
        this.protectedAsset = protectedAsset;
    }

    ProtectedAsset protectedAsset;

    public Map<String, String> getAdditionalInformation() {
        if (additionalInformation == null) {
            additionalInformation = new HashMap<String, String>();
        }
        return additionalInformation;
    }

    public void setAdditionalInformation(Map<String, String> additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    Map<String, String> additionalInformation;
}
