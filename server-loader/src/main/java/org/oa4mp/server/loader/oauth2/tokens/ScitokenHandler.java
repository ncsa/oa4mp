package org.oa4mp.server.loader.oauth2.tokens;

import org.oa4mp.server.loader.oauth2.claims.AbstractAccessTokenHandler;
import org.oa4mp.server.loader.oauth2.claims.PayloadHandlerConfigImpl;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import static org.oa4mp.delegation.server.server.claims.OA2Claims.AUDIENCE;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.SUBJECT;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/21/20 at  4:55 PM
 */
public class ScitokenHandler extends AbstractAccessTokenHandler {
    public ScitokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }

    //    String ST_SCOPE = "scope";
    String ST_CLIENT_IDENTIFIER = "cid";
    String VERSION_2_0 = "scitoken:2.0";
    String ST_VERSION_CLAIM = "ver";
    String ST_AUDIENCE_SCOPE_CAPUT = "aud:";


    public String getUsernameClaimKey() {
        return ((SciTokenConfig) getPhCfg().getPayloadConfig()).getUsernameClaimKey();
    }

    /**
     * NOTE that the SciTokens spec. changed substantially form version 1.0 to 2.0. we  do
     * not support 1.0. Then again, nobody does really.
     *
     * @return
     */
    protected String getVersion() {
        return VERSION_2_0;
    }

    @Override
    public void init() throws Throwable {
        super.init();
        JSONObject sciTokens = getPayload();

        // subject is optional
        sciTokens.put(SUBJECT, transaction.getUsername());
        //sciTokens.put(ST_CLIENT_IDENTIFIER, transaction.getOA2Client().getIdentifierString());
        sciTokens.put(ST_VERSION_CLAIM, getVersion()); // make sure set for inter-operability with others
        // strip off audience requests. These are passed in as scopes as per
        // https://scitokens.org/technical_docs/Claims
        // This is probably going away in the SciTokens spec and, it seems, nobody ever did it.
        // Keep for a bit until we are sure it is dead, then remove it.
/*        List<String> aud = new JSONArray();
        for (String x : transaction.getScopes()) {
            if (x.startsWith(ST_AUDIENCE_SCOPE_CAPUT)) {
                // Be really dumb about this. They say an audience scope starts with a given string,
                // so just amputate the marker.
                aud.add(x.substring(ST_AUDIENCE_SCOPE_CAPUT.length()));
            }
        }
        if (0 < aud.size()) {
            getAtData().put(AUDIENCE, aud);
        }*/
    }

    @Override
    public void finish(boolean doTemplates, boolean isQuery) throws Throwable {
        super.finish(doTemplates, isQuery);
        // SciTokens specification has a special value for the audience of ANY that is a string.
        // As per spec., do not return an array like ["ANY"] but replace it with the single
        // string "ANY"
        // First time it hits this the audience is converted. Only SciTokens allows for this specific
        // value.
        // Update 3/29/2022 -- in practice, a lot of SciToken clients that send a long a string as the audience
        // will only process a simple string in the response. They are supposed to accept an array
        // of them, but do not. If it's a singleton, convert it to a string.
        if (getPayload().get(AUDIENCE) instanceof JSONArray) {
            JSONArray audience = getPayload().getJSONArray(AUDIENCE);
            if(audience.size() == 1){
                getPayload().put(AUDIENCE, audience.get(0));
            }
/*
            if (audience.size() == 1 && audience.getString(0).equals("ANY")) {
                getAtData().put(AUDIENCE, "ANY");
            }
*/

        }
    }
}
