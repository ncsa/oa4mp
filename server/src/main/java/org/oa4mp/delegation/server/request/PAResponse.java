package org.oa4mp.delegation.server.request;


import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.ProtectedAsset;

import java.util.Map;

/**
 * Additional information in the form of a map may be supplied. These will be prepended to the response
 * in the form key=value, each on a line. The protected asset will then be appended to the end of this list.
 * Not setting the addtional information will cause it to be ignored.
 * <p>Created by Jeff Gaynor<br>
 * on May 13, 2011 at  12:34:30 PM
 */
public interface PAResponse extends IssuerResponse {
    public ProtectedAsset getProtectedAsset();

    public void setProtectedAsset(ProtectedAsset protectedAsset);

    public AccessToken getAccessToken();

    public Map<String, String> getAdditionalInformation();

    public void setAdditionalInformation(Map<String, String> additionalInformation);
}
