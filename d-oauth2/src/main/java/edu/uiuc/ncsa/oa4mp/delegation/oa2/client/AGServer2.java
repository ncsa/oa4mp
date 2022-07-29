package edu.uiuc.ncsa.oa4mp.delegation.oa2.client;

import edu.uiuc.ncsa.oa4mp.delegation.client.request.AGRequest;
import edu.uiuc.ncsa.oa4mp.delegation.client.request.AGResponse;
import edu.uiuc.ncsa.oa4mp.delegation.client.server.AGServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.NonceHerder;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Scopes;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Hex;

import java.net.URI;
import java.security.SecureRandom;
import java.util.HashMap;

/**
 * This class manages the client call to the authorization grant server
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:27 PM
 */
public class AGServer2 extends ASImpl implements AGServer, OA2Constants {
    /**
     * The number of bytes in the random state string sent to the server.
     */
    public static int STATE_LENGTH = 16;
    ServiceClient serviceClient;

    public ServiceClient getServiceClient() {
        return serviceClient;
    }

    public AGServer2(ServiceClient serviceClient) {
        super(serviceClient.host());
        this.serviceClient = serviceClient;
    }

    SecureRandom secureRandom = new SecureRandom();

    /**
     * Accepts AGRequest, obtains auth code, packs said authCode into AGResponse
     * and returns AGResponse
     *
     * @param agRequest Authorization grant request
     * @return Authorization grant response
     */
    public AGResponse processAGRequest(AGRequest agRequest) {
        String nonce = NonceHerder.createNonce();
        HashMap m = new HashMap();
        m.put(RESPONSE_TYPE, RESPONSE_TYPE_CODE);
        m.put(CLIENT_ID, agRequest.getClient().getIdentifierString());
        m.put(SCOPE, OA2Scopes.SCOPE_OPENID + " " + OA2Scopes.SCOPE_MYPROXY + " " + OA2Scopes.SCOPE_PROFILE);
        m.put(REDIRECT_URI, agRequest.getParameters().get(REDIRECT_URI));
        byte[] bytes = new byte[STATE_LENGTH];
        secureRandom.nextBytes(bytes);
        String sentState = Hex.encodeHexString(bytes);
        m.put(STATE, sentState);
        m.put(NONCE, nonce);
        m.put(PROMPT, PROMPT_LOGIN);
        if (agRequest.getParameters().containsKey(RESPONSE_MODE)) {
            m.put(RESPONSE_MODE, agRequest.getParameters().get(RESPONSE_MODE));
        }
        String responseString = getServiceClient().doGet(m);
        //System.out.println(getClass().getSimpleName() + ".processAGRequest: raw response=" + responseString);
        JSONObject json = JSONObject.fromObject(responseString);
        String accessCode = json.getString(AUTHORIZATION_CODE);
        if (accessCode == null) {
            throw new IllegalArgumentException("Error: server did not return an access code.");
        }
        String state = json.getString(STATE);
        if (!sentState.equals(state)) {
            throw new IllegalStateException("The state string returned by the server does not match the one sent.");
        }
        HashMap map = new HashMap();
        // optional but send it along if it is there.
        map.put(STATE, state);

        AuthorizationGrantImpl agi = new AuthorizationGrantImpl(URI.create(accessCode));
        AGResponse agr = new AGResponse(agi);
        agr.setParameters(map);
        return agr;
    }
}
