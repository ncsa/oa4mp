package edu.uiuc.ncsa.oa4mp.delegation.client.request;


import edu.uiuc.ncsa.oa4mp.delegation.common.token.ProtectedAsset;

import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 13, 2011 at  3:39:12 PM
 */
public class PAResponse extends BasicResponse {
    public PAResponse(ProtectedAsset protectedAsset) {
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
