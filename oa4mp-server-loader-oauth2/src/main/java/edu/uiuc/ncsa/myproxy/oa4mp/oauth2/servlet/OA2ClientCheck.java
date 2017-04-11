package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import org.apache.http.HttpStatus;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/17/14 at  12:57 PM
 */
public class OA2ClientCheck {
    /**
     * Note that all of the exceptions thrown here are because the callback cannot be verified, hence it is unclear
     * where the error is to be sent.
     * @param client
     * @param redirect
     */
    public static void check(Client client, String redirect) {

        if(client == null){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "no client id", HttpStatus.SC_BAD_REQUEST);
        }
        if (!(client instanceof OA2Client)) {
            throw new NFWException("Internal error: Client is not an OA2Client");
        }

        OA2Client oa2Client = (OA2Client) client;


        boolean foundCB = false;
        if(oa2Client.getCallbackURIs() == null){
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "client has not registered any callback URIs", HttpStatus.SC_BAD_REQUEST);
        }
        for (String uri : oa2Client.getCallbackURIs()) {
            if (uri.equals(redirect)) {
                foundCB = true;
                break;
            }
        }

        if (!foundCB) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "The given redirect \"" + redirect + "\" is not valid for this client", HttpStatus.SC_BAD_REQUEST);

            //throw new GeneralException("Error: The given redirect is not valid for this client");
        }
    }
}
