package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.AccessTokenHandlerInterface;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.SRE_REQ_ACCESS_TOKEN;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * Only create an access token handler if you need some special handling, otherwise the
 * default simple token will be used.
 * <p>Created by Jeff Gaynor<br>
 * on 7/21/20 at  2:50 PM
 */
public class AbstractAccessTokenHandler extends AbstractPayloadHandler implements AccessTokenHandlerInterface {
    AccessToken accessToken;

    public AbstractAccessTokenHandler(AbstractPayloadHandlerConfig payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }

    /**
     * The underlying {@link JSONObject} that contains the claims that go in to this access token.
     * Note that the {@link #getClaims()} call will retrieve the user metadata and is not the same as
     * the access token contents!
     *
     * @return
     */
    public JSONObject getAtData() {
        return transaction.getATData();
    }

    public void setAtData(JSONObject atData) {
        transaction.setATData(atData);
    }

    @Override
    public void init() throws Throwable {
        // set some standard claims.
        if (getAtData().isEmpty()) {
            setAccountingInformation();
        }
    }

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_ACCESS_TOKEN, getAtData());
    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {

    }

    @Override
    public void checkClaims() throws Throwable {

    }

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return new ArrayList<>();
    }

    @Override
    public void finish() throws Throwable {
    }

    /**
     * Gets the AT data object (which has all the claims in it) and returns a signed access token.
     * This does <b>not</b> set the access token in the transaction but leaves up to the calling
     * application what to do, since different tokens have different contracts.
     *
     * @return
     */
    @Override
    public AccessToken getSignedAT(JSONWebKey key) {
        if (key == null) {
            throw new IllegalArgumentException("Error: A null JSON web key was encountered");
        }
        if (getAtData().isEmpty()) return null;
        try {
            String at = JWTUtil2.createJWT(getAtData(), key);
            URI x = URI.create(at);
            return new AccessTokenImpl(x);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }

            e.printStackTrace();
            throw new GeneralException("Could not create signed token", e);
        }
    }

    @Override
    public void saveState() throws Throwable {
        if (transaction != null && oa2se != null) {
            oa2se.getTransactionStore().save(transaction);
        } else {
            trace(this, "In saveState: either env or transaction null. Nothing saved.");
        }
    }

    @Override
    public void setAccountingInformation() {
        JSONObject atData = getAtData();

        atData.put(NOT_VALID_BEFORE, (System.currentTimeMillis() - 5000L) / 1000L); // not before is 5 minutes before current
        atData.put(ISSUER, oa2se.getIssuer());
        atData.put(EXPIRATION, System.currentTimeMillis() / 1000L + 900L);
        atData.put(ISSUED_AT, System.currentTimeMillis() / 1000L);
        if (transaction.getAccessToken() != null) {
            atData.put(JWT_ID, transaction.getAccessToken().getToken());
        }
        setAtData(atData);

    }

    @Override
    public void refreshAccountingInformation() {
        setAccountingInformation();
    }

    public AccessToken getAccessToken() {
        return transaction.getAccessToken();
    }

    public void setAccessToken(AccessToken accessToken) {
        transaction.setAccessToken(accessToken);
    }
}
