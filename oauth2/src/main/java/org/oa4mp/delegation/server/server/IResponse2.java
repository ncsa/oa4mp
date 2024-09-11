package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:07 PM
 */
public abstract class IResponse2 implements IssuerResponse {
    public boolean isOIDC() {
        return isOIDC;
    }

    public void setIsOIDC(boolean isOIDC) {
        this.isOIDC = isOIDC;
    }

    boolean isOIDC = true;

    public IResponse2(boolean isOIDC) {
        this.isOIDC = isOIDC;
    }

    public void setParameters(Map<String, String> parameters) {
        this.parameters = parameters;
    }

    Map<String,String> parameters;
    public Map<String, String> getParameters() {
        return parameters;
    }

}
