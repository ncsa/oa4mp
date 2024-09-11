package org.oa4mp.delegation.server.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.AbstractIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.issuers.PAIssuer;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.PARequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.PAResponse;
import org.oa4mp.delegation.common.token.TokenForge;

import java.net.URI;

/**
 * Protected asset (cert) issuer for Oauth 2 class
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  5:05 PM
 */
public class PAI2 extends AbstractIssuer implements PAIssuer {
    boolean isOIDC = true;
    /** Constructor
    @param tokenForge Token forge to use
    @param address URI of cert request endpoint
    */
    public PAI2(TokenForge tokenForge, URI address,boolean isOIDC) {
        super(tokenForge, address);
        this.isOIDC = isOIDC;
    }

    /**
    Process cert request
    @param paRequest Protected asset request object
    @return Protected asset response object
    */
    public PAResponse processProtectedAsset(PARequest paRequest) {
        try {
         //   Map<String, String> reqParamMap = OA2Utilities.getParameters(paRequest.getServletRequest());

            PAIResponse2 paResponse = new PAIResponse2(isOIDC);
            paResponse.setAccessToken(paRequest.getAccessToken()); // return the right access token with this, so the caller can track it
            return paResponse;
        } catch (Exception x) {
            if(x instanceof RuntimeException){
                throw (RuntimeException)x;
            }
            throw new GeneralException(" could not get protected asset", x);
        }
    }
}
