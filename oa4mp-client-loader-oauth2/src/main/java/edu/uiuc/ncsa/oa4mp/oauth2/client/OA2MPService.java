package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.AssetResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPService;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.delegation.client.request.*;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.*;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.NonceHerder;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATServer2;
import edu.uiuc.ncsa.security.oauth_2_0.client.DS2;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.InvalidNonceException;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.PEMFormatUtil;
import net.sf.json.JSONObject;

import java.net.URI;
import java.security.KeyPair;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.RFC8693Constants.*;

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
                String msg = "Error: The private key is missing. The internal state of the asset is invalid";
                NFWException x = new NFWException((msg));
                getEnvironment().getMyLogger().warn(msg, x);
                throw x;
            }
            try {
                asset.setCertReq(CertUtil.createCertRequest(keyPair));
            } catch (Throwable t) {
                String msg = "Error: could not create cert request.";
                getEnvironment().getMyLogger().warn(msg, t);
                if (t instanceof RuntimeException) {
                    throw (RuntimeException) t;
                }
                throw new GeneralException(msg, t);
            }
        }

    }

    @Override
    protected Map<String, String> getATParameters(Asset asset, AuthorizationGrant ag, Verifier v) {
        Map<String, String> m = super.getATParameters(asset, ag, v);
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
        Map<String, String> map = new HashMap<>();
        map.putAll(additionalParameters);
        dar.setParameters(map);
        return processAtRequest(asset, dar);
    }

    @Override
    public void preRequestCert(Asset asset, Map parameters) {
        // do nothing here in this case. Protocol says add cert req before getCert.
        if (!parameters.containsKey(getEnvironment().getConstants().get(CALLBACK_URI_KEY))) {
            parameters.put(getEnvironment().getConstants().get(CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        }
        OA2Asset a = (OA2Asset) asset;
        a.setState(NonceHerder.createNonce());
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

        //parameters.put(OA2Constants.REDIRECT_URI, delegationRequest.getParameters().get(OA2Constants.REDIRECT_URI));
        parameters.put(STATE, a.getState()); // random state is ok.
        parameters.put(NONCE, a.getNonce());
        parameters.put(PROMPT, PROMPT_LOGIN);
        parameters.putAll(((OA2ClientEnvironment) getEnvironment()).getAdditionalParameters());
    }


    public OA2MPService(ClientEnvironment environment) {
        super(environment);
    }

    public ATResponse2 getAccessToken(OA2Asset asset, AuthorizationGrant ag, Map<String, String> additionalParameters) {
        DelegatedAssetRequest dar = new DelegatedAssetRequest();
        dar.setAuthorizationGrant(ag);
        dar.setClient(getEnvironment().getClient());
        Map<String, String> m1 = getATParameters(asset, ag, null);
        if (additionalParameters != null) {
            m1.putAll(additionalParameters);
        }
        dar.setParameters(m1);
        return processAtRequest(asset, dar);
    }

    private ATResponse2 processAtRequest(OA2Asset asset, DelegatedAssetRequest dar) {
        ATResponse2 atResponse2 = (ATResponse2) getEnvironment().getDelegationService().getAT(dar);
        asset.setIssuedAt((Date) atResponse2.getParameters().get(OA2Claims.ISSUED_AT));
        asset.setUsername((String) atResponse2.getParameters().get(OA2Claims.SUBJECT));
        if (atResponse2.getParameters().containsKey(NONCE) && !NonceHerder.hasNonce((String) atResponse2.getParameters().get(NONCE))) {
            throw new InvalidNonceException("Unknown nonce.");
        }
        NonceHerder.removeNonce((String) atResponse2.getParameters().get(NONCE)); // prevent replay attacks.

        asset.setAccessToken((AccessTokenImpl) atResponse2.getAccessToken());
        asset.setRefreshToken(atResponse2.getRefreshToken());

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
        Map<String, String> m1 = getAssetParameters(a);

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
    protected AssetResponse getCert(Asset a, AuthorizationGrant ag, Verifier v) {
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

    public RTResponse refresh(String identifier, Map additionalParameters) {
        OA2Asset asset = (OA2Asset) getAssetStore().get(identifier);
        if (asset == null) return null;
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        RTRequest rtRequest = new RTRequest(getEnvironment().getClient(), additionalParameters);
        rtRequest.setAccessToken(asset.getAccessToken());
        rtRequest.setRefreshToken(asset.getRefreshToken());
        RTResponse rtResponse = ds2.refresh(rtRequest);
        asset.setAccessToken((AccessTokenImpl) rtResponse.getAccessToken());
        asset.setRefreshToken(rtResponse.getRefreshToken());
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
        //UserInfo ui = (UserInfo) JSONObject.toBean(json, UserInfo.class);
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
        OA2Asset OA2Asset = (OA2Asset) getAssetStore().get(id);
        AssetResponse assetResponse = getCert(OA2Asset.getAccessToken().getToken(), null);
        OA2Asset.setCertificates(assetResponse.getX509Certificates());
        OA2Asset.setUsername(assetResponse.getUsername());
        getAssetStore().save(OA2Asset);
        return OA2Asset;
    }

    /*
    Starting here is support for RFC 8693, token exchange
     */

    /**
     * Use this to either just get a new refresh token (getAT = false) or to use the refresh token
     * to get a new access token (most usual case).
     *
     * @param asset
     * @param token
     * @param additionalParameters
     * @param getAT
     * @return
     */
    public JSONObject exchangeRefreshToken(OA2Asset asset, TokenImpl token,
                                           Map additionalParameters,
                                           boolean getAT) {
        HashMap<String, String> parameterMap = new HashMap<>();
        parameterMap.put(SUBJECT_TOKEN, token.getToken());

        if (getAT) {
            parameterMap.put(SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
            parameterMap.put(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        } else {
            parameterMap.put(SUBJECT_TOKEN_TYPE, REFRESH_TOKEN_TYPE);
            parameterMap.put(REQUESTED_TOKEN_TYPE, REFRESH_TOKEN_TYPE);
        }
        
        if (additionalParameters != null) {
            parameterMap.putAll(additionalParameters);
        }
        return exchangeIt(asset, parameterMap);
    }

    /**
     * Use the access token to get another access token. This is certainly a supported case, but
     * not a usual one. Mostly you use a refresh token to get another access token.
     *
     * @param asset
     * @param accessToken
     * @param additionalParams
     * @return
     */
    public JSONObject exchangeAccessToken(OA2Asset asset, AccessToken accessToken, Map<String, String> additionalParams) {
        Map parameterMap = new HashMap();
        parameterMap.put(SUBJECT_TOKEN, accessToken.getToken());
        parameterMap.put(SUBJECT_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        parameterMap.put(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE);
        parameterMap.putAll(additionalParams);

        return exchangeIt(asset, parameterMap);
    }

    /**
     * Actual workhorse. Takes the token and the type then does the exchange.
     *
     * @param asset
     * @param additionalParameters
     * @return
     */
    protected JSONObject exchangeIt(OA2Asset asset, Map<String, String> additionalParameters) {
        ServiceClient serviceClient = getServiceClient();
        Map parameterMap = new HashMap<>();
        if (additionalParameters != null) {
            parameterMap.putAll(additionalParameters);
        }
        parameterMap.put(OA2Constants.GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        Client client = getEnvironment().getClient();
        String rawResponse = serviceClient.getRawResponse(parameterMap, client.getIdentifierString(), client.getSecret());

        DebugUtil.trace(this, "raw response = " + rawResponse);
        JSONObject json = JSONObject.fromObject(rawResponse);
        updateExchangedAsset(asset, json);
        String rawToken = json.getString(OA2Constants.ACCESS_TOKEN);
        JSONWebKeys keys = JWTUtil2.getJsonWebKeys(serviceClient, ((OA2ClientEnvironment) getEnvironment()).getWellKnownURI());
        JSONObject j = null;
        try {
            // See if its a SciToken
            j = JWTUtil2.verifyAndReadJWT(rawToken, keys);
        } catch (Throwable t) {
            j = new JSONObject();
            if (json.getString(ISSUED_TOKEN_TYPE).equals(REFRESH_TOKEN_TYPE)) {
                j.put(REFRESH_TOKEN, rawToken);
            } else {
                j.put(OA2Constants.ACCESS_TOKEN, rawToken);
            }
        }
        return j;

    }


    public ServiceClient getServiceClient() {
        ATServer2 atServer2 = (ATServer2) getEnvironment().getDelegationService().getAtServer();
        return atServer2.getServiceClient();
    }

    protected void updateExchangedAsset(OA2Asset asset, JSONObject claims) {
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

}
