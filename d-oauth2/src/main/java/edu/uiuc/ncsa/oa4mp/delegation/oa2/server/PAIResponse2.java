package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.PAResponse;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.MyX509Certificates;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.ProtectedAsset;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * Protected asset (cert) issuer response for OIDC. This has to include the servlet request since the headers have
 * to be processed for various bits of information.
 * <p>Created by Jeff Gaynor<br>
 * on 6/5/13 at  9:31 AM
 */
public class PAIResponse2 extends IResponse2 implements PAResponse {
    public PAIResponse2(boolean isOIDC) {
        super(isOIDC);
    }

    ProtectedAsset protectedAsset;
    AccessToken accessToken;
    Map<String, String> additionalInformation;

    /**
    Getter for access token
    @return access token associated with request
     */
    public AccessToken getAccessToken() {
        return accessToken;
    }

    /**
    Setter for access token
    @param accessToken Access token to use
     */
    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    /**
    Getter for protected asset (cert)
    @return protected asset
     */
    public ProtectedAsset getProtectedAsset() {
        return protectedAsset;
    }

    /**
    Setter for protected asset (cert)
    @param protectedAsset  Protected asset
     */
    public void setProtectedAsset(ProtectedAsset protectedAsset) {
        this.protectedAsset = protectedAsset;
    }

    /**
    Getter for additional information
    @return Map containing addition information (param, value)
     */
    public Map<String, String> getAdditionalInformation() {
        if (additionalInformation == null) {
            additionalInformation = new HashMap<String, String>();
        }
        return additionalInformation;
    }

    /**
    Setter for additional information
    @param additionalInformation Additional information Map (param, value)
     */
    public void setAdditionalInformation(Map<String, String> additionalInformation) {
        this.additionalInformation = additionalInformation;
    }

    /**
    Write cert response to output stream
    @param response Response to write to
     */
    public void write(HttpServletResponse response) throws IOException {

        if (protectedAsset == null) {
            throw new GeneralException("Error, no protected asset =");
        }
        if (!(getProtectedAsset() instanceof MyX509Certificates)) {
            throw new NotImplementedException("Error, this implementation can only serialize MyX509Certificates and a protected asset of type \""
                    + getProtectedAsset().getClass().getName() + "\" was found instead");
        }
        try {
            MyX509Certificates certs = (MyX509Certificates) getProtectedAsset();
            if(certs == null || certs.getX509CertificatesPEM() == null){
                throw new GeneralException("Error: No certificate found.");
            }

            response.setContentType("text/plain");
            OutputStream out = response.getOutputStream();
            OutputStreamWriter osw = new OutputStreamWriter(out);

            out.write(certs.getX509CertificatesPEM().getBytes());
            out.flush();
            out.close();


        } catch (Exception x) {
            throw new GeneralException(x);
        }
    }
}
