package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
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

import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.*;

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
        // NOTE that the refresh token is NOT signed! So we ignore the key if passed or not.

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
            rt0.setLifetime(1000 * (getRTData().getLong(EXPIRATION) - getRTData().getLong(ISSUED_AT)));
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
        super.handleResponse(resp);
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                setClaims((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                DebugUtil.trace(this, "Setting claims to " + claims.toString(2));
                //sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                setExtendedAttributes((JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES));
                setRTData((JSONObject) resp.getReturnedValues().get(SRE_REQ_ACCESS_TOKEN));
                return;
            case RC_NOT_RUN:
                return;
        }
    }

    @Override
    public void checkClaims() throws Throwable {

    }

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return new ArrayList<>();
    }

    @Override
    public void finish(String execPhase) throws Throwable {
        JSONObject rtData = transaction.getRTData();
        if (transaction.getRefreshToken() != null) {
            rtData.put(JWT_ID, transaction.getRefreshToken().getToken());
        }
        long proposedLifetime = (rtData.getLong(EXPIRATION) - rtData.getLong(ISSUED_AT))*1000;
        if (proposedLifetime <= 0) {
            proposedLifetime = transaction.getMaxRtLifetime();
        } else {
            proposedLifetime = Math.min(proposedLifetime, transaction.getMaxRtLifetime());
        }
        rtData.put(EXPIRATION, (rtData.getLong(ISSUED_AT) * 1000 + proposedLifetime) / 1000);
        transaction.setRefreshTokenLifetime(proposedLifetime);
        setRTData(rtData);
    }

    @Override
    public void saveState() throws Throwable {
        switch (getResponseCode()) {
            case RC_NOT_RUN:
                break;
            case RC_OK:
                if (transaction != null && oa2se != null) {
                    transaction.setUserMetaData(getClaims());  // It is possible that the claims were updated. Save them.
                    transaction.setRTData(getRTData());
                    DebugUtil.trace(this, ".saveState: done updating transaction.");
                }
            case RC_OK_NO_SCRIPTS:
                oa2se.getTransactionStore().save(transaction);
                break;

        }
/*
        if (transaction != null && oa2se != null && getResponseCode() == RC_OK) {
            transaction.setUserMetaData(getClaims());  // It is possible that the claims were updated. Save them.
            transaction.setRTData(getRTData());

            oa2se.getTransactionStore().save(transaction);
            DebugUtil.trace(this, ".saveState: done saving transaction.");
        } else {
            trace(this, "In saveState: either env or transaction null. Nothing saved.");
        }
*/


    }

    protected RefreshTokenConfig getRTConfig() {
        return (RefreshTokenConfig) getPhCfg().getClientConfig();
    }

    @Override
    public void setAccountingInformation() {
        JSONObject rtData = transaction.getRTData();
        if(!StringUtils.isTrivial(getRTConfig().getIssuer())){
            rtData.put(ISSUER, getRTConfig().getIssuer());
        }
        /*
        A note about audiences and resources. We are free to put these where we want in the complex
        refresh token, so if they are in the rt data they are written to the token.
        In point of fact, there is an RFC https://tools.ietf.org/html/rfc8707 if we want
        to support that, which details accepting them as part of the auth request and also
        later as a parameter to the token endpoint. In that case, the response must have the
        resource, not the token.

        The idea is that specifying these (they are optional) in the RT means the client
        needs them. They are optional.
         */
        if(getRTConfig().getAudience() != null && !getRTConfig().getAudience().isEmpty()) {
            rtData.put(AUDIENCE, listToString(getRTConfig().getAudience()));
        }

        if(getRTConfig().getResource() != null && !getRTConfig().getResource().isEmpty()) {
            rtData.put(RESOURCE, listToString(getRTConfig().getResource()));
        }

        long currentTS = System.currentTimeMillis();

        if (0 < getRTConfig().getLifetime()) {
            rtData.put(EXPIRATION, (System.currentTimeMillis() + getRTConfig().getLifetime()) / 1000L);
        } /*else {
            rtData.put(EXPIRATION, (System.currentTimeMillis() / 1000L) + 900L); // 15 minutes.
        }
*/

        rtData.put(NOT_VALID_BEFORE, (currentTS - 5000L) / 1000L); // not before is 5 minutes before current
        DebugUtil.trace(this, "@@Setting refresh lifetime = " + transaction.getRefreshTokenLifetime());
        rtData.put(ISSUED_AT, currentTS / 1000L);
      //  rtData.put(EXPIRATION, (currentTS + transaction.getRefreshTokenLifetime()) / 1000L);
        if (transaction.getRefreshToken() != null) {
            rtData.put(JWT_ID, transaction.getRefreshToken().getToken());
        }
        setRTData(rtData); // since if it was empty, then no such object has been set in the transaction.
    }

    @Override
    public void refreshAccountingInformation() {
        setAccountingInformation();
    }
}
