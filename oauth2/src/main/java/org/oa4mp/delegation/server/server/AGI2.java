package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AGIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.AGRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import org.oa4mp.delegation.server.OA2TokenForge;
import org.oa4mp.delegation.server.OA2Utilities;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

/**
 * Authorization grant issuer class.  Creates and issues
 * authorization grants.
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:03 PM
 */
public class AGI2 extends AbstractIssuer implements AGIssuer {
    boolean isOIDC = true;

    /**
     * Constructor
     *
     * @param tokenForge Token forge to use
     * @param address    URI of authorization endpoint
     */
    public AGI2(TokenForge tokenForge, URI address, boolean isOIDC) {
        super(tokenForge, address);
        this.isOIDC = isOIDC;
    }

    protected OA2TokenForge getTF() {
        return (OA2TokenForge) tokenForge;
    }

    /**
     * Accepts authorization grant request and returns response with an authorization
     * code
     *
     * @param authorizationGrantRequest
     * @return Authorization grant response
     */
    public IssuerResponse processAGRequest(AGRequest authorizationGrantRequest) {

        // Get values out of AGRequest and populate variables
        Map<String, String> reqParamMap;
        if (authorizationGrantRequest.getServletRequest() == null) {
            reqParamMap = new HashMap<>();
        } else {
            reqParamMap = OA2Utilities.getParameters(authorizationGrantRequest.getServletRequest());
        }

        // TODO Check parameters passed in

        //AuthorizationGrant ag = tokenForge.getAuthorizationGrant(); // get a fresh new shiny one.
        AuthorizationGrantImpl ag = getTF().createToken((AGRequest2) authorizationGrantRequest); // get a fresh new shiny one.
        AGIResponse2 agResponse = new AGIResponse2(isOIDC);
        agResponse.setGrant(ag);
        agResponse.setParameters(reqParamMap);

        return agResponse;
    }
}
