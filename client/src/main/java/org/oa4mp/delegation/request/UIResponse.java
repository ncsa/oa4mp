package org.oa4mp.delegation.request;

import org.oa4mp.delegation.common.token.AccessToken;

/**
 * Created with IntelliJ IDEA.
 * User: wedwards
 * Date: 1/30/14
 * Time: 4:45 PM
 *
 * For now/development, we'll only look at the raw JSON, but should
 * eventually add functionality to unpack it and populate UserInfo
 * fields
 */
public class UIResponse extends ATResponse{

    private String rawJSON;

    public UIResponse(AccessToken at, String rawJSON) {
        super(at);
        this.rawJSON = rawJSON;
    }

    public String getRawJSON() {
        return rawJSON;
    }

    public void setRawJSON(String rawJSON) {
        this.rawJSON = rawJSON;
    }
}
