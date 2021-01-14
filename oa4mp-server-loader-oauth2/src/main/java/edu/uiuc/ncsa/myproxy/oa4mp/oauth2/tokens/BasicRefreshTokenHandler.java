package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.RefreshTokenHandlerInterface;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.SRE_REQ_REFRESH_TOKEN;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/5/20 at  9:18 AM
 */
public class BasicRefreshTokenHandler extends AbstractPayloadHandler implements RefreshTokenHandlerInterface {
    public BasicRefreshTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }

    @Override
    public RefreshToken getRefreshToken() {
        return transaction.getRefreshToken();
    }


    @Override
    public void setRefreshToken(RefreshToken refreshToken) {
        transaction.setRefreshToken(refreshToken);
    }

    public JSONObject getRTData() {
        return transaction.getRTData();
    }

    public void setRTData(JSONObject rtData) {
        transaction.setRTData(rtData);
    }

    @Override
    public RefreshToken getSignedRT(JSONWebKey key) {
        if (getRTData().isEmpty()) return null;
        /*
         Special case: If the claim has a single entry then that is the raw token. Return that. This allows
         handlers in QDL to decide not to return a JWT and just return a standard identifier.
          */
        if (getRTData().size() == 1) {
            String k = String.valueOf(getRTData().keySet().iterator().next());
            String v = String.valueOf(getRTData().get(k));
            oa2se.info("Single value in refresh token for \"" + transaction.getOA2Client().getIdentifierString() + "\" found. Setting token value to " + v);
            return new RefreshTokenImpl(URI.create(v));
        }
        if (!getRTData().containsKey(JWT_ID)) {
            throw new IllegalStateException("Error: no " + JWT_ID + ". Cannot create refresh token");
        }
        try {
            if (key == null) {
                key = new JSONWebKey();
                key.algorithm = JWTUtil2.NONE_JWT;
            }
            String at = JWTUtil2.createJWT(getRTData(), key);
            URI jti = URI.create(getRTData().getString(JWT_ID));
            RefreshTokenImpl rt0 = new RefreshTokenImpl(at, jti);
            rt0.setLifetime(getRTData().getLong(EXPIRATION) - getRTData().getLong(ISSUED_AT));
            return rt0;
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            e.printStackTrace();
            throw new GeneralException("Could not create signed refresh token", e);
        }
    }

    @Override
    public void init() throws Throwable {
        // set some standard claims.
        if (getRTData().isEmpty()) {
            setAccountingInformation();
        }
    }

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_REFRESH_TOKEN, getRTData());

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

    @Override
    public void saveState() throws Throwable {

    }

    @Override
    public void setAccountingInformation() {
        JSONObject rawRT = transaction.getRTData();
        long currentTS = System.currentTimeMillis();
        //     wlcg.put(SUBJECT, transaction.getUserMetaData().getString("eppn"));
        rawRT.put(ISSUER, oa2se.getIssuer());
        rawRT.put(NOT_VALID_BEFORE, (currentTS - 5000L) / 1000L); // not before is 5 minutes before current
        DebugUtil.trace(this, "@@Setting refresh lifetime = " + transaction.getRefreshTokenLifetime());
        rawRT.put(ISSUED_AT, currentTS / 1000L);
        rawRT.put(EXPIRATION, (currentTS + transaction.getRefreshTokenLifetime()) / 1000L);
        if (transaction.getRefreshToken() != null) {
            rawRT.put(JWT_ID, transaction.getRefreshToken().getToken());
        }
        setRTData(rawRT); // since if it was empty, then no such object has been set in the transaction.
    }

    @Override
    public void refreshAccountingInformation() {
        setAccountingInformation();
    }
}
