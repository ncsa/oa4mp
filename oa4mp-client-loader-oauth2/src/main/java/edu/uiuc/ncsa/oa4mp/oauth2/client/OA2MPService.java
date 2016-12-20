package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.*;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.client.request.*;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.oauth_2_0.NonceHerder;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.client.ATResponse2;
import edu.uiuc.ncsa.security.oauth_2_0.client.DS2;
import edu.uiuc.ncsa.security.oauth_2_0.server.InvalidNonceException;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import edu.uiuc.ncsa.security.util.pkcs.PEMFormatUtil;
import net.sf.json.JSONObject;

import java.net.URLEncoder;
import java.security.KeyPair;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;
import static edu.uiuc.ncsa.security.delegation.client.AbstractClientEnvironment.CERT_REQUEST_KEY;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/21/14 at  2:50 PM
 */
public class OA2MPService extends OA4MPService {
    private static final boolean MANUAL_TEST = false;
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
        m.put(OA2Constants.NONCE, a.getNonce());
        m.put(OA2Constants.STATE, a.getState());
        return m;
    }

    protected String requestedScopes;

    /**
     * Override this if you need to request custom scopes (i.e. those not in the basic OA4MP specification) for a server.
     * This returns a blank delimited list of scopes, e.g. "openid email profile". Note that if you
     * override this method, the openid scope must always be included or the server will refuse to service the request.
     * The basic operation is to take the basic scopes for the OA4MP OIDC spec and add any that are specified in the
     * configuration file in the "scopes" element.
     *
     * @return
     */
    public String getRequestedScopes() {
        if (requestedScopes == null) {
            boolean firstPass = true;
            String[] basicScopes = OA2Scopes.basicScopes;
            Collection<String> targetScopes = new HashSet<>();
            Collection<String> scopeList = ((OA2ClientEnvironment) getEnvironment()).getScopes();
            targetScopes.addAll(scopeList);
            for (String x : basicScopes) {
                targetScopes.add(x);
            }
            requestedScopes = "";
            for (String scope : targetScopes) {
                if (firstPass) {
                    requestedScopes = scope;
                    firstPass = false;
                } else {
                    requestedScopes = requestedScopes + " " + scope;
                }
            }
        }
        return requestedScopes;
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

        parameters.put(OA2Constants.RESPONSE_TYPE, OA2Constants.AUTHORIZATION_CODE);
        //parameters.put(OA2Constants.CLIENT_ID, delegationRequest.getClient().getIdentifierString());
        parameters.put(OA2Constants.SCOPE, getRequestedScopes());
        //parameters.put(OA2Constants.REDIRECT_URI, delegationRequest.getParameters().get(OA2Constants.REDIRECT_URI));
        parameters.put(OA2Constants.STATE, a.getState()); // random state is ok.
        parameters.put(OA2Constants.NONCE, a.getNonce());
        parameters.put(OA2Constants.PROMPT, OA2Constants.PROMPT_LOGIN);
    }

/*
    @Override
    public void postRequestCert(Asset asset, OA4MPResponse oa4MPResponse) {
        super.postRequestCert(asset, oa4MPResponse);
        OA2Asset a = (OA2Asset) asset;
    }
*/

    public OA2MPService(ClientEnvironment environment) {
        super(environment);
    }

    public ATResponse2 getAccessToken(OA2Asset asset, AuthorizationGrant ag) {
        DelegatedAssetRequest dar = new DelegatedAssetRequest();
        dar.setAuthorizationGrant(ag);
        dar.setClient(getEnvironment().getClient());
        Map<String, String> m1 = getATParameters(asset, ag, null);
        dar.setParameters(m1);


        ATResponse2 atResponse2 = (ATResponse2) getEnvironment().getDelegationService().getAT(dar);
        asset.setIssuedAt((Date) atResponse2.getParameters().get(OA2Claims.ISSUED_AT));
        asset.setUsername((String) atResponse2.getParameters().get(OA2Claims.SUBJECT));
        if(!NonceHerder.hasNonce((String) atResponse2.getParameters().get(OA2Constants.NONCE))){
            throw new InvalidNonceException("Unknown nonce.");
        }
        NonceHerder.removeNonce((String) atResponse2.getParameters().get(OA2Constants.NONCE)); // prevent replay attacks.

        asset.setAccessToken(atResponse2.getAccessToken());
        asset.setRefreshToken(atResponse2.getRefreshToken());

        getAssetStore().save(asset);
        return atResponse2;
    }

    /**
     * This should only be invoked during a manual test by setting the MANUAL_TEST flag to true. it will print out
     * interim results from the getCert call which can then be cut and pasted into a curl call. This is intended to be
     * a low-level debugging aid and if this test flag is enabled, then the client will be unable to actually get a cert.
     * @param a
     * @param m1
     * @return
     */
    protected AssetResponse manualTest(OA2Asset a, Map<String,String> m1){
        try {
            System.err.println(getClass().getSimpleName() + ".getAccessToken: Returned parameters");
            System.err.println("access token=" + URLEncoder.encode(a.getAccessToken().getToken(), "UTF-8") + "");
            System.err.println("&client_id=" + URLEncoder.encode(getEnvironment().getClient().getIdentifierString(),"UTF-8") + "");
            System.err.println("&client_secret=" + URLEncoder.encode(getEnvironment().getClient().getSecret(), "UTF-8") + "");
            System.err.println("&"+CERT_REQUEST_KEY + "=" + URLEncoder.encode(m1.get(CERT_REQUEST_KEY),"UTF-8") + "");
        }catch(Throwable t){
            System.err.println(getClass().getSimpleName() + ".getCert: attempt to get response parameters failed.");
            t.printStackTrace();
        }
        return null; // This will cause all sorts of stuff to fail later, which we want,
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
            throw new GeneralException("Could no create cert request", e);
        }
        a.setPrivateKey(keyPair.getPrivate());
        a.setCertReq(certReq);
        Map<String, String> m1 = getAssetParameters(a);

        preGetCert(a, m1);
        if(MANUAL_TEST) {return manualTest(a,m1);}
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
    public OA2Asset refresh(String identifier) {
        OA2Asset asset = (OA2Asset) getAssetStore().get(identifier);
        if (asset == null) return null;
        DS2 ds2 = (DS2) getEnvironment().getDelegationService();
        RTRequest rtRequest = new RTRequest(getEnvironment().getClient(), null);
        rtRequest.setAccessToken(asset.getAccessToken());
        rtRequest.setRefreshToken(asset.getRefreshToken());
        RTResponse rtResponse = ds2.refresh(rtRequest);
        asset.setAccessToken(rtResponse.getAccessToken());
        asset.setRefreshToken(rtResponse.getRefreshToken());
        getAssetStore().remove(asset.getIdentifier()); // clear out
        getAssetStore().save(asset);
        return asset;
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


}
