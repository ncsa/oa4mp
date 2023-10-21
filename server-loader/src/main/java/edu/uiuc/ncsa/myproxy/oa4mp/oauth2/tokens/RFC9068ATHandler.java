package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractAccessTokenHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC9068Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.AUDIENCE;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.SUBJECT;

/**
 * Handler for access tokens as per <a href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</a>.
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/21 at  8:10 AM
 */
public class RFC9068ATHandler extends AbstractAccessTokenHandler implements RFC9068Constants {
    public RFC9068ATHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }


    @Override
    public void init() throws Throwable {
        super.init();
        JSONObject accessToken = getPayload();

        accessToken.put(SUBJECT, transaction.getUsername());
        accessToken.put(RFC8693Constants.CLIENT_ID, transaction.getOA2Client().getIdentifierString());
        if(getUserMetaData().containsKey(AUTHENTICATION_CLASS_REFERENCE)){
            accessToken.put(AUTHENTICATION_CLASS_REFERENCE, getUserMetaData().get(AUTHENTICATION_CLASS_REFERENCE));
        }
        if(getUserMetaData().containsKey(AUTHENTICATION_METHOD_REFERENCE)){
            accessToken.put(AUTHENTICATION_METHOD_REFERENCE, getUserMetaData().get(AUTHENTICATION_METHOD_REFERENCE));
        }

        if(transaction.getAuthTime()!=null) {
            // It is possible there is no auth time.
            accessToken.put(AUTHENTICATION_TIME, transaction.getAuthTime().getTime() / 1000); // Must be in seconds.
        }
        // According to the spec., if there is a resource in the request, it should be used as the audience
        if(transaction.hasResource() && !transaction.getResource().isEmpty()){
            if(transaction.getResource().size()==1) {
                accessToken.put(OA2Claims.AUDIENCE, transaction.getResource().get(0));
            }else{
                JSONArray array = new JSONArray();
                array.addAll(transaction.getResource());
                accessToken.put(OA2Claims.AUDIENCE, array);
            }
        }
        if(!accessToken.containsKey(AUDIENCE)){
            // Last ditch. If this is not otherwise set, set it to the client id.
            accessToken.put(AUDIENCE, transaction.getClient().getIdentifierString());
        }
    }

    @Override
    public AccessTokenImpl getSignedPayload(JSONWebKey key) {
        return getSignedPayload(key, HEADER_TYPE);
    }
}
