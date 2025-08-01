package org.oa4mp.client.loader;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.crypto.PEMFormatUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONObject;
import org.oa4mp.client.api.Asset;
import org.oa4mp.client.api.AssetResponse;
import org.oa4mp.client.api.ClientEnvironment;
import org.oa4mp.client.api.OA4MPService;
import org.oa4mp.delegation.client.request.*;
import org.oa4mp.delegation.common.storage.clients.Client;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.MyX509Certificates;
import org.oa4mp.delegation.common.token.impl.*;
import org.oa4mp.delegation.server.NonceHerder;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.UserInfo;
import org.oa4mp.delegation.server.client.ATResponse2;
import org.oa4mp.delegation.server.client.ATServer2;
import org.oa4mp.delegation.server.client.DS2;
import org.oa4mp.delegation.server.client.RFC7523Utils;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.delegation.server.server.InvalidNonceException;
import org.oa4mp.delegation.server.server.claims.OA2Claims;

import java.net.URI;
import java.security.KeyPair;
import java.util.*;

import static org.oa4mp.client.api.ClientEnvironment.CALLBACK_URI_KEY;
import static org.oa4mp.delegation.server.OA2Constants.*;
import static org.oa4mp.delegation.server.server.RFC8693Constants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/21/14 at  2:50 PM
 */
public class OA2MPService extends OA4MPService {

    @Override
    public void preGetCert(Asset asset, Map parameters) {
        super.preGetCert(asset, parameters);
        OA2Asset a = (OA2Asset) asset;
        parameters.put(ClientEnvironment.CERT_REQUEST_KEY, PEMFormatUtil.bytesToChunkedString(asset.getCertReq().getEncoded()));
        if (!parameters.containsKey(getEnvironment().getConstants().get(CALLBACK_URI_KEY))) {
            parameters.put(getEnvironment().getConstants().get(CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        }
        if (0 <= getEnvironment().getCertLifetime()) {
            parameters.put(ClientEnvironment.CERT_LIFETIME_KEY, getEnvironment().getCertLifetime());
        }
        if (asset.getCertificates() != null) {

            // We have some, so restart the sequence to get more.
            MyPKCS10CertRequest certRequest = asset.getCertReq();
            KeyPair keyPair = null;
            if (certRequest == null) {
                // ok... generate a new keypair
                try {
                    keyPair = KeyUtil.generateKeyPair();
                } catch (Throwable e) {
                    String msg = "Unable to generate a new keypair.";
                    getEnvironment().getMyLogger().warn(msg, e);
                    if (e instanceof RuntimeException) {
                        throw (RuntimeException) e;
                    }
                    throw new GeneralException(msg, e);
                }
                asset.setPrivateKey(keyPair.getPrivate());
            } else {
                // need to public key.
                keyPair = new KeyPair(certRequest.getPublicKey(), asset.getPrivateKey());
            }
            if (asset.getPrivateKey() == null) {
                String msg = "The private key is missing. The internal state of the asset is invalid";
                NFWException x = new NFWException((msg));
                getEnvironment().getMyLogger().warn(msg, x);
                throw x;
            }
            try {
                asset.setCertReq(CertUtil.createCertRequest(keyPair));
            } catch (Throwable t) {
                String msg = "could not create cert request.";
                getEnvironment().getMyLogger().warn(msg, t);
                if (t instanceof RuntimeException) {
                    throw (RuntimeException) t;
                }
                throw new GeneralException(msg, t);
            }
        }

    }

    @Override
    protected Map<String, Object> getATParameters(Asset asset, AuthorizationGrant ag) {
        Map<String, Object> m = super.getATParameters(asset, ag);
        OA2Asset a = (OA2Asset) asset;
        if (a == null) {
            throw new GeneralException("Asset not found. You may need to clear your browser cookies.");
        }
        m.put(NONCE, a.getNonce());
        m.put(STATE, a.getState());
        return m;
    }

    //  protected String requestedScopes;

    /**
     * Override this if you need to request custom scopes (i.e. those not in the basic OA4MP specification) for a server.
     * This returns a blank delimited list of scopes, e.g. "openid email profile". Note that if you
     * override this method, and the server id OIDC, then the openid scope must always
     * be included or the server will refuse to service the request.
     * The basic operation is to take the basic scopes for the OA4MP OIDC spec and add any that are specified in the
     * configuration file in the "scopes" element.
     *
     * @return
     */
    public String getRequestedScopes() {
        boolean firstPass = true;
        String requestedScopes = "";
        Collection<String> targetScopes = new HashSet<>();
        Collection<String> scopeList = ((OA2ClientEnvironment) getEnvironment()).getScopes();
        targetScopes.addAll(scopeList);
        for (String scope : targetScopes) {
            if (firstPass) {
                requestedScopes = scope;
                firstPass = false;
            } else {
                requestedScopes = requestedScopes + " " + scope;
            }
        }
        return requestedScopes;
    }

    public ATResponse2 rfc8628Request(OA2Asset asset, String deviceCode, Map<String, String> additionalParameters) {
        DelegatedAssetRequest dar = new DelegatedAssetRequest();
        dar.setRfc8628(true);
        dar.setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(deviceCode)));
        dar.setClient(getEnvironment().getClient());
        dar.setKeyID(getEnvironment().getKid());
        Map<String, Object> map = new HashMap<>();
        map.putAll(additionalParameters);
        dar.setParameters(map);
        return processAtRequest(asset, dar);
    }

    @Override
    public void preRequestCert(Asset asset, Map parameters) {
        // do nothing here in this case. Protocol says add cert req before getCert.
        if (!parameters.containsKey(getEnvironment().getConstants().get(CALLBACK_URI_KEY))) {
            if (getEnvironment().getCallback() == null) {
                throw new IllegalArgumentException("missing callback in configuration");
            }
            parameters.put(getEnvironment().getConstants().get(CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        }
        OA2Asset a = (OA2Asset) asset;
        a.setNonce(NonceHerder.createNonce());
        // Next is for testing exception handling on the server. This creates an unsupported request which should fail everytime.
        //parameters.put(OA2Constants.REQUEST, "My_request");

        parameters.put(RESPONSE_TYPE, AUTHORIZATION_CODE);
        // Add in extra scopes if any.
        String s = getRequestedScopes(); // reads them from the client
        if (parameters.containsKey(SCOPE)) {
            s = s + " " + parameters.get(SCOPE);
        }
        parameters.put(SCOPE, s);

        // Allow the user to specify this in case they really need to track it themselves.
        if (parameters.containsKey(STATE)) {
            a.setState((String) parameters.get(STATE));
        } else {
            String state = NonceHerder.createNonce();
            a.setState(state);
            parameters.put(STATE, state); // random state is ok.
        }
        if (parameters.containsKey(NONCE)) {
            a.setNonce((String) parameters.get(NONCE));
        } else {
            String none = NonceHerder.createNonce();
            parameters.put(NONCE, none);
            a.setNonce(none);
        }
        parameters.put(PROMPT, PROMPT_LOGIN);
        parameters.putAll(((OA2ClientEnvironment) getEnvironment()).getAdditionalParameters());
    }


    public OA2MPService(ClientEnvironment environment) {
        super(environment);
    }

    public ATResponse2 getAccessToken(OA2Asset asset, AuthorizationGrant ag,
                                      Map<String, Object> additionalParameters) {
        DelegatedAssetRequest dar = new DelegatedAssetRequest();
        dar.setAuthorizationGrant(ag);
        dar.setClient(getEnvironment().getClient());
        dar.setKeyID(getEnvironment().getKid());
        Map<String, Object> m1 = new HashMap<>();
        m1.putAll(getATParameters(asset, ag));
        if (additionalParameters != null) {
            m1.putAll(additionalParameters);
        }
        dar.setParameters(m1);
        return processAtRequest(asset, dar);
    }


    private ATResponse2 processAtRequest(OA2Asset asset, DelegatedAssetRequest dar) {
        ATResponse2 atResponse2 = (ATResponse2) getEnvironment().getDelegationService().getAT(dar);
        asset.setIssuedAt(new Date(atResponse2.getAccessToken().getIssuedAt()));
        //asset.setIssuedAt((Date) atResponse2.getParameters().get(OA2Claims.ISSUED_AT));
        if (atResponse2.hasIDToken() && atResponse2.getIdToken().getPayload().containsKey(OA2Claims.SUBJECT)) {
            asset.setUsername(atResponse2.getIdToken().getPayload().getString(OA2Claims.SUBJECT));
            asset.setIdToken(atResponse2.getIdToken());
        }
        if (atResponse2.getParameters().containsKey(NONCE) && !NonceHerder.hasNonce((String) atResponse2.getParameters().get(NONCE))) {
            throw new InvalidNonceException("Unknown nonce.");
        }
        NonceHerder.removeNonce((String) atResponse2.getParameters().get(NONCE)); // prevent replay attacks.


        asset.setAccessToken((AccessTokenImpl) atResponse2.getAccessToken());
        if (atResponse2.hasRefreshToken()) {
            asset.setRefreshToken(atResponse2.getRefreshToken());
        }
        getAssetStore().save(asset);
        return atResponse2;
    }

    public ATResponse2 getAccessToken(OA2Asset asset, AuthorizationGrant ag) {
        return getAccessToken(asset, ag, null);
    }


    public AssetResponse getCert(OA2Asset a,
                                 ATResponse2 atResponse2) {
        KeyPair keyPair = getNextKeyPair();
        MyPKCS10CertRequest certReq = null;
        try {
            certReq = CertUtil.createCertRequest(keyPair, a.getUsername());
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could not create cert request", e);
        }
        a.setPrivateKey(keyPair.getPrivate());
        a.setCertReq(certReq);
        Map<String, Object> m1 = new HashMap<>();
                m1.putAll(getAssetParameters(a));

        preGetCert(a, m1);

        DelegatedAssetResponse daResp = getEnvironment().getDelegationService().getCert(atResponse2, getEnvironment().getClient(), m1);

        AssetResponse par = new AssetResponse();
        MyX509Certificates myX509Certificate = (MyX509Certificates) daResp.getProtectedAsset();
        par.setX509Certificates(myX509Certificate.getX509Certificates());
        postGetCert(a, par);
        a.setCertificates(par.getX509Certificates());
        getEnvironment().getAssetStore().save(a);
        return par;

    }

    @Override
    protected AssetResponse getCert(Asset a, AuthorizationGrant ag) {
        OA2Asset asset = (OA2Asset) a;
        ATResponse2 atResp = getAccessToken(asset, ag);
        return getCert(asset, atResp);
    }

    /**
     * This will take the identifier and make the necessary calls to the service to update the refresh
     * token and access token. This returns the asset or null if no such asset exists.
     *
     * @param identifier
     */
    public RTResponse refresh(String identifier) {
        return refresh(identifier, null);
    }

    public RTResponse refresh(String assetID, Map additionalParameters) {
        OA2Asset asset = getAsset2(assetID);
        //if (asset == null) return null;
        if (asset == null) {
            throw new NoSuchAssetException("Asset with id \"" + assetID + "\" not found.");
        }
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        RTRequest rtRequest = new RTRequest(getEnvironment().getClient(), getEnvironment().getKid(), additionalParameters);
        rtRequest.setAccessToken(asset.getAccessToken());
        rtRequest.setRefreshToken(asset.getRefreshToken());
        RTResponse rtResponse = ds2.refresh(rtRequest);
        asset.setAccessToken((AccessTokenImpl) rtResponse.getAccessToken());
        if (rtResponse.hasRefreshToken()) {
            asset.setRefreshToken(rtResponse.getRefreshToken());
        }
        if (rtResponse.hasIDToken()) {
            asset.setIdToken(rtResponse.getIdToken());
        }
        getAssetStore().remove(asset.getIdentifier()); // clear out
        getAssetStore().save(asset);
        return rtResponse;

    }

    public UserInfo getUserInfo(String identifier) {
        OA2Asset asset = getAsset2(identifier);
        if (asset == null || asset.getAccessToken() == null) return null;
        UIRequest uiRequest = new UIRequest(asset.getAccessToken());
        uiRequest.setClient(getEnvironment().getClient());
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        UIResponse resp = ds2.getUserInfo(uiRequest);
        JSONObject json = JSONObject.fromObject(resp.getRawJSON());
        UserInfo ui = new UserInfo();
        ui.setMap(json); // return everything, even specialized fields.
        return ui;
    }


    protected OA2Asset getAsset2(String id) {
        return (OA2Asset) getAssetStore().get(id);
    }

    /**
     * Note that this requires the identifier, not a token.
     *
     * @param id
     * @return
     */
    public OA2Asset getCert(String id) {
        OA2Asset asset = getAsset2(id);
        if (asset == null) {
            throw new NoSuchAssetException("Asset \"" + id + "\" not found");
        }
        AssetResponse assetResponse = getCert(asset.getAccessToken().getToken(), null);
        asset.setCertificates(assetResponse.getX509Certificates());
        asset.setUsername(assetResponse.getUsername());
        getAssetStore().save(asset);
        return asset;
    }

    /*
    Starting here is support for RFC 8693, token exchange
     */

    /**
     * Use this to either just get a new refresh token (getAT = false) or to use the refresh token
     * to get a new access token (most usual case).
     *
     * @param asset
     * @param subjectToken
     * @param additionalParameters
     * @param requestedTokenType
     * @return
     */
    public JSONObject exchangeRefreshToken(OA2Asset asset,
                                           TokenImpl subjectToken,
                                           Map additionalParameters,
                                           int requestedTokenType,
                                           String subjectType,
                                           boolean isErsatz) {
        HashMap<String, String> parameterMap = new HashMap<>();
        parameterMap.put(SUBJECT_TOKEN, subjectToken.getToken());
        switch (subjectType) {
            case ACCESS_TOKEN:
                parameterMap.put(SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
                break;
            case REFRESH_TOKEN:
                parameterMap.put(SUBJECT_TOKEN_TYPE, REFRESH_TOKEN_TYPE);
                break;
            case ID_TOKEN:
                parameterMap.put(SUBJECT_TOKEN_TYPE, ID_TOKEN_TYPE);
                break;
            default:
                throw new IllegalArgumentException("unknown subject type \"" + subjectType + "\"");
        }
        switch (requestedTokenType) {
            case EXCHANGE_ACCESS_TOKEN:
                parameterMap.put(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
                break;
            case EXCHANGE_REFRESH_TOKEN:
                parameterMap.put(REQUESTED_TOKEN_TYPE, REFRESH_TOKEN_TYPE);
                break;
            case EXCHANGE_ID_TOKEN:
                parameterMap.put(REQUESTED_TOKEN_TYPE, ID_TOKEN_TYPE);
                break;
            default:
            case EXCHANGE_DEFAULT:
                // do not set it
        }

        if (additionalParameters != null) {
            parameterMap.putAll(additionalParameters);
        }
        return exchangeIt(asset, parameterMap, isErsatz);
    }

    public final static int EXCHANGE_ID_TOKEN = 100;
    public final static int EXCHANGE_ACCESS_TOKEN = 50;
    public final static int EXCHANGE_REFRESH_TOKEN = 10;
    public final static int EXCHANGE_DEFAULT = 0;

    /**
     * Use the access token to get another access token. This is certainly a supported case, but
     * not a usual one. Mostly you use a refresh token to get another access token.
     *
     * @param asset
     * @param accessToken
     * @param additionalParams
     * @return
     */
/*    public JSONObject exchangeAccessToken(OA2Asset asset, AccessToken accessToken, Map<String, String> additionalParams) {
        Map parameterMap = new HashMap();
        parameterMap.put(SUBJECT_TOKEN, accessToken.getToken());
        parameterMap.put(SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        parameterMap.put(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        parameterMap.putAll(additionalParams);

        return exchangeIt(asset, parameterMap);
    }*/

    /**
     * Actual workhorse. Takes the token and the type then does the exchange.  This updates the asset
     * and returns then entire response fromm the server.
     *
     * @param asset
     * @param additionalParameters
     * @return
     */
    protected JSONObject exchangeIt(OA2Asset asset, Map<String, String> additionalParameters,
                                    boolean isErsatz) {
        ServiceClient serviceClient = getServiceClient();
        Map parameterMap = new HashMap<>();
        if (additionalParameters != null) {
            parameterMap.putAll(additionalParameters);
        }
        parameterMap.put(OA2Constants.GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        Client client = getEnvironment().getClient();
        OA2ClientEnvironment oa2ClientEnvironment = (OA2ClientEnvironment) getEnvironment();
        String rawResponse;
        if (oa2ClientEnvironment.hasJWKS()) {
            rawResponse = RFC7523Utils.doPost(serviceClient,
                    client,
                    oa2ClientEnvironment.getAccessTokenUri(),
                    oa2ClientEnvironment.getKid(),
                    parameterMap);
        } else {
            rawResponse = serviceClient.doGet(parameterMap, client.getIdentifierString(), client.getSecret());
        }

        DebugUtil.trace(this, "raw response = " + rawResponse);
        JSONObject json = JSONObject.fromObject(rawResponse);
        JSONWebKeys keys = MyOtherJWTUtil2.getJsonWebKeys(serviceClient, ((OA2ClientEnvironment) getEnvironment()).getWellKnownURI());
        if (isErsatz) {
            // only return types supported for forking is access (everything) or refresh token only.
            asset.setRefreshToken(TokenFactory.createRT(json.getString(REFRESH_TOKEN)));
            if (!json.getString(ISSUED_TOKEN_TYPE).equals(REFRESH_TOKEN_TYPE)) {
                // all tokens get updated.
                asset.setIdToken(TokenFactory.createIDT(json.getString(ACCESS_TOKEN)));
                asset.setAccessToken(TokenFactory.createAT(json.getString(ACCESS_TOKEN)));
            }
        } else {
            switch (json.getString(ISSUED_TOKEN_TYPE)) {
                case REFRESH_TOKEN_TYPE:
                    asset.setRefreshToken(TokenFactory.createRT(json.getString(REFRESH_TOKEN)));
                    break;
                case ACCESS_TOKEN_TYPE:
                    asset.setAccessToken(TokenFactory.createAT(json.getString(ACCESS_TOKEN)));
                    break;
                case ID_TOKEN_TYPE:
                    //asset.setIdToken(TokenFactory.createIDT(json.getString(ACCESS_TOKEN)).getPayload());
                    asset.setIdToken(TokenFactory.createIDT(json.getString(ACCESS_TOKEN)));
                    break;
                default:
                    throw new IllegalArgumentException("unknown token type \"" + json.getString(ISSUED_TOKEN_TYPE) + "\"");
            }

        }
        getEnvironment().getAssetStore().save(asset);
        return json;

    }


    public ServiceClient getServiceClient() {
        ATServer2 atServer2 = (ATServer2) getEnvironment().getDelegationService().getAtServer();
        return atServer2.getServiceClient();
    }

    public ServiceClient getRFC8623ServiceClient() {
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        return ds2.getRfc8623Server().getServiceClient();
    }

    protected void updateExchangedAsset(OA2Asset asset, JSONObject claims) {
        //   NEWupdateExchangedAsset(asset, claims);
    }

    /**
     * Note that NO verification is done for this! It will take a raw string and a flag and return
     * a token (access or refresh)
     *
     * @param rawToken
     * @param isRT
     * @return
     */
    protected TokenImpl figureOutToken(String rawToken, boolean isRT) {
        try {
            JSONObject[] json = MyOtherJWTUtil2.readJWT(rawToken);
            URI jti = URI.create(json[MyOtherJWTUtil2.PAYLOAD_INDEX].getString(OA2Claims.JWT_ID));
            if (isRT) {
                return new RefreshTokenImpl(rawToken, jti);
            }
            return new AccessTokenImpl(rawToken, jti);
        } catch (IllegalArgumentException iax) {
            // so this is not a JWT.
        }
        if (isRT) {
            return new RefreshTokenImpl(URI.create(rawToken));
        }
        return new AccessTokenImpl(URI.create(rawToken));
    }

/*
    protected void NEWupdateExchangedAsset(OA2Asset asset, JSONObject claims) {
        boolean saveAsset = false;
        if (claims.containsKey(ISSUED_TOKEN_TYPE)) {
            String accessToken = claims.getString(ACCESS_TOKEN);
            String refreshToken = null;
            if (claims.containsKey(REFRESH_TOKEN)) {
                refreshToken = claims.getString(REFRESH_TOKEN);
            }
            JSONObject idToken = null;
            if (claims.get(ISSUED_TOKEN_TYPE).equals(ID_TOKEN_TYPE)) {
                idToken = claims.getJSONObject(ACCESS_TOKEN); // This is re-used for ID token as per spec.
                accessToken = ""; // zero it out so it is not mis-identified later
            }
            if (idToken != null && !idToken.isEmpty()) {
                asset.setIdToken(idToken);
                saveAsset = true;
            }
            if (accessToken != null && !accessToken.isEmpty()) {
                asset.setAccessToken((AccessTokenImpl) figureOutToken(accessToken, false));
                saveAsset = true;
            }

            // Then the returned token is a refresh token, as per spec.
            if (refreshToken != null && !refreshToken.isEmpty()) {
                asset.setRefreshToken((RefreshTokenImpl) figureOutToken(refreshToken, true));
                saveAsset = true;
            }
        }

        if (saveAsset) {
            getEnvironment().getAssetStore().save(asset);
        }
    }
*/

    protected void OLDupdateExchangedAsset(OA2Asset asset, JSONObject claims) {
        boolean saveAsset = false;
        if (claims.containsKey(ISSUED_TOKEN_TYPE)) {
            String token = claims.getString(ACCESS_TOKEN);

            if (claims.getString(ISSUED_TOKEN_TYPE).equals(ACCESS_TOKEN_TYPE)) {
                if (token != null && !token.isEmpty()) {
                    AccessTokenImpl at = new AccessTokenImpl(URI.create(token));
                    asset.setAccessToken(at);
                    saveAsset = true;
                }

            }
            if (claims.getString(ISSUED_TOKEN_TYPE).equals(REFRESH_TOKEN_TYPE)) {
                // Then the returned token is a refresh token, as per spec.
                if (token != null && !token.isEmpty()) {
                    RefreshTokenImpl refreshToken = new RefreshTokenImpl(URI.create(token));
                    asset.setRefreshToken(refreshToken);
                    saveAsset = true;
                }

            }
        }
        if (saveAsset) {
            getEnvironment().getAssetStore().save(asset);
        }
    }

    public boolean revoke(OA2Asset dummyAsset, boolean revokeRT) {
        RFC7009Request request = new RFC7009Request();
        // always set the access token since it is used to create the bearer token
        // in the request
        request.setAccessToken(dummyAsset.getAccessToken());
        request.setClient(getEnvironment().getClient());
        request.setKeyID(getEnvironment().getKid());
        request.setTokenEndpoint(getEnvironment().getAccessTokenUri());
        if (revokeRT) {
            request.setRefreshToken(dummyAsset.getRefreshToken());
        }
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
     //   try {
            ds2.rfc7009(request);
            return true;
/*        } catch (Throwable t) {
            DebugUtil.trace(this, "revoke encountered a "
                    + t.getClass().getSimpleName()
                    + ": \""
                    + t.getMessage() + "\" ");
        }
        return false;*/
    }

    public JSONObject introspect(OA2Asset asset, boolean doRT) {
        RFC7662Request request = new RFC7662Request();
        if (doRT) {
            request.setRefreshToken(asset.getRefreshToken());
        } else {
            request.setAccessToken(asset.getAccessToken());
        }
        request.setClient(getEnvironment().getClient());
        request.setKeyID(getEnvironment().getKid());
        request.setTokenEndpoint(getEnvironment().getAccessTokenUri());
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        return ds2.rfc7662(request).getResponse();
    }

    public JSONObject rfc6749_4_4(OA2Asset asset, Map parameters, boolean useRFC7523) {
        RFC6749_4_4Request req;
        if (useRFC7523) {
            if (!getEnvironment().hasJWKS()) {
                throw new IllegalArgumentException("sorry, but this client does not have any keys.");
            }
            // do RFC 7523 stuff
            req = new RFC6749_4_4Request(getEnvironment().getClient(), parameters,getEnvironment().getKid());
        } else {
            if (StringUtils.isTrivial(getEnvironment().getClient().getSecret())) {
                throw new IllegalArgumentException("sorry, but this client does not have a secret. Cannot start a flow that requires a secret.");
            }
            parameters.put(CLIENT_ID, getEnvironment().getClient().getIdentifierString());
            parameters.put(CLIENT_SECRET, getEnvironment().getClient().getSecret());
            req = new RFC6749_4_4Request();
        }
        req.setParameters(parameters);
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        RFC6749_4_4_Response response = ds2.rfc6749_4_4(req);
        JSONObject json = response.getJSON();
        if (json.containsKey(NONCE) && !NonceHerder.hasNonce((String) json.get(NONCE))) {
            throw new InvalidNonceException("Unknown nonce.");
        }
        NonceHerder.removeNonce((String) json.get(NONCE)); // prevent replay attacks.
        if(!json.containsKey(ACCESS_TOKEN)) {
            throw new IllegalArgumentException("No access token found in server response");
        }
        AccessTokenImpl at = TokenFactory.createAT(json.getString(ACCESS_TOKEN));
        asset.setAccessToken(at);
        if(json.containsKey(ID_TOKEN)){
            IDTokenImpl idt = TokenFactory.createIDT(json.getString(ID_TOKEN));
            asset.setIdToken(idt);
        }
        if(json.containsKey(REFRESH_TOKEN)) {
            RefreshTokenImpl rt = TokenFactory.createRT(json.getString(REFRESH_TOKEN));
            asset.setRefreshToken(rt);
        }else{
          asset.setRefreshToken(null);
        }
        getAssetStore().save(asset);
        return json;
    }

    public JSONObject rfc7523(OA2Asset asset, Map parameters) {
        RFC7523Request request = new RFC7523Request();
        request.setKeyID(getEnvironment().getKid());
        request.setClient(getEnvironment().getClient());
        request.setParameters(parameters);
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        RFC7523Response response = ds2.rfc7523(request);
        JSONObject json = response.getResponse();
        asset.setUsername((String) json.get(OA2Claims.SUBJECT));
        if (json.containsKey(NONCE) && !NonceHerder.hasNonce((String) json.get(NONCE))) {
            throw new InvalidNonceException("Unknown nonce.");
        }
        NonceHerder.removeNonce((String) json.get(NONCE)); // prevent replay attacks.
        if (!json.containsKey(ACCESS_TOKEN)) {
            throw new IllegalArgumentException("No access token found in server response");
        }
        AccessTokenImpl at = TokenFactory.createAT(json.getString(ACCESS_TOKEN));
        asset.setIssuedAt(new Date(at.getIssuedAt()));

        asset.setAccessToken(at);
        RefreshTokenImpl rt = null;
        if (json.containsKey(REFRESH_TOKEN)) {
            // the refresh token is optional, so if it is missing then there is nothing to do.
            rt = TokenFactory.createRT(json.getString(REFRESH_TOKEN));
            asset.setRefreshToken(rt);
        }
        if (response.getIdToken() != null) {
            asset.setIdToken(response.getIdToken());
        }
        getAssetStore().save(asset);


        return response.getResponse();
    }
}
