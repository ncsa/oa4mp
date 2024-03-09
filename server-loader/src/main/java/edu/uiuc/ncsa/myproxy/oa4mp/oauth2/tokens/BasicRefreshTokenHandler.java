package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.PayloadHandlerConfigImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.RefreshToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.MyOtherJWTUtil2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.RefreshTokenHandlerInterface;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.*;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.SRE_POST_AUTH;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.SRE_REQ_REFRESH_TOKEN;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/5/20 at  9:18 AM
 */
public class BasicRefreshTokenHandler extends AbstractPayloadHandler implements RefreshTokenHandlerInterface {
    public static final String REFRESH_TOKEN_DEFAULT_HANDLER_TYPE = "default";
    public static final String REFRESH_TOKEN_BASIC_HANDLER_TYPE = "refresh";

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



    @Override
    public JSONObject getPayload() {
        if(payload == null){
           payload = transaction.getRTData();
           if(payload == null){
               payload = new JSONObject();
           }
        }
        return payload;
    }

    public void setRTData(JSONObject rtData) {
        setPayload(rtData);
    }

    @Override
    public RefreshTokenImpl getSignedPayload(JSONWebKey key) {
        return getSignedPayload(key, null);
    }

    @Override
    public RefreshTokenImpl getSignedPayload(JSONWebKey key, String headerType) {
        if (getPayload().isEmpty()) return null;
        /*
         Special case: If the claim has a single entry then that is the raw token. Return that. This allows
         handlers in QDL to decide not to return a JWT and just return a standard identifier.
          */
        if (getPayload().size() == 1) {
            String k = String.valueOf(getPayload().keySet().iterator().next());
            String v = String.valueOf(getPayload().get(k));
            oa2se.info("Single value in refresh token for \"" + client.getIdentifierString() + "\" found. Setting token value to " + v);
            return new RefreshTokenImpl(URI.create(v));
        }
        if (!getPayload().containsKey(JWT_ID)) {
            throw new IllegalStateException("no " + JWT_ID + ". Cannot create refresh token");
        }
        try {
            if (key == null) {
                key = new JSONWebKey();
                key.algorithm = MyOtherJWTUtil2.NONE_JWT;
            }
            String at = MyOtherJWTUtil2.createJWT(getPayload(), key);
            return TokenFactory.createRT(at);
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
      //  if (getPayload().isEmpty()) {
            setAccountingInformation();
       // }
    }

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_REFRESH_TOKEN, getPayload());
    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        super.handleResponse(resp);
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
            //    setUserMetaData((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                setRTData((JSONObject) resp.getReturnedValues().get(SRE_REQ_REFRESH_TOKEN));
                return;
            case RC_NOT_RUN:
                return;
        }
    }

    @Override
    public void checkClaims() throws Throwable {

    }

    /*
     At this point, the refresh handler does not run any user meta data sources.
     */
    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return new ArrayList<>();
    }



    @Override
    public void finish(String execPhase) throws Throwable {
        if(transaction.getRefreshTokenLifetime() == 0L){
            throw new IllegalStateException("refresh lifetime disabled for this client");
        }
        JSONObject rtData = getPayload();
        // if the token identifier has been updated, record this.
        if(transaction.getRefreshToken() != null){
            // default
                rtData.put(JWT_ID, transaction.getRefreshToken().getToken());
        }
        if(hasTXRecord()){
            // Fixes CIL-971
            TXRecord txRecord = getTXRecord();
            if(RFC8693Constants.REFRESH_TOKEN_TYPE.equals(txRecord.getTokenType())){
                rtData.put(JWT_ID, txRecord.getIdentifierString());
            }
        }
        refreshAccountingInformation();
        doServerVariables(rtData, null);
    }

    @Override
    public void saveState(String execPhase) throws Throwable {
         if(execPhase.equals(SRE_POST_AUTH)){
             transaction.setRTData(getPayload());
             transaction.setRefreshTokenLifetime(getPayload().getLong(EXPIRATION)*1000L);
         }
         super.saveState(execPhase);
    }


    protected RefreshTokenConfig getRTConfig() {
        return (RefreshTokenConfig) getPhCfg().getClientConfig();
    }

    @Override
    public void setAccountingInformation() {
        JSONObject rtData = getPayload();
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


        if (transaction.getRefreshToken() != null) {
            rtData.put(JWT_ID, transaction.getRefreshToken().getToken());
        }
        refreshAccountingInformation();
    }

    @Override
    public void refreshAccountingInformation() {
        JSONObject rtData = getPayload();
        long lifetime = ClientUtils.computeRefreshLifetime(transaction, client, oa2se);
        long issuedAt = System.currentTimeMillis();
        long expiresAt = issuedAt + lifetime;
        rtData.put(EXPIRATION, expiresAt / 1000L);
        rtData.put(NOT_VALID_BEFORE, (issuedAt - 5000L) / 1000L); // not before is 5 minutes before current
        rtData.put(ISSUED_AT, issuedAt / 1000L);
        
        if(hasTXRecord()){
            getTXRecord().setLifetime(lifetime);
            getTXRecord().setExpiresAt(expiresAt);
            getTXRecord().setIssuedAt(issuedAt);
        }
    }
}
