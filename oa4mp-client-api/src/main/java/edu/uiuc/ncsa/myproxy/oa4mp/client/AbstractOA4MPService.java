package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.MemoryAssetStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetRequest;
import edu.uiuc.ncsa.security.delegation.client.request.DelegatedAssetResponse;
import edu.uiuc.ncsa.security.delegation.client.request.DelegationRequest;
import edu.uiuc.ncsa.security.delegation.client.request.DelegationResponse;
import edu.uiuc.ncsa.security.delegation.token.AuthorizationGrant;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.Verifier;
import edu.uiuc.ncsa.security.util.pkcs.Base64String;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import java.net.URI;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/26/13 at  11:27 AM
 */
public abstract class AbstractOA4MPService {
    AssetStore assetStore;

    protected AssetStore getAssetStore() {
        if (assetStore == null) {
            if (getEnvironment().hasAssetStore()) {
                assetStore = getEnvironment().getAssetStore();
            } else {
                assetStore = new MemoryAssetStore(getAssetProvider());
            }
        }
        return assetStore;
    }

    public static final String SKIN_PARAMETER = "skin";


    protected AbstractOA4MPService(ClientEnvironment environment) {
        this.environment = environment;
    }

    public ClientEnvironment getEnvironment() {
        return environment;
    }

    ClientEnvironment environment;

    public abstract void preRequestCert(Asset asset, Map parameters);

    public abstract void preGetCert(Asset asset, Map parameters);

    public abstract void postRequestCert(Asset asset, OA4MPResponse oa4MPResponse);

    public abstract void postGetCert(Asset asset, AssetResponse assetResponse);

    /**
     * This will make the request with whatever defaults are in effect for the client. You can override these
     * by supplying them as key-value pairs in the {@link #requestCert(java.util.Map)} call.
     *
     * @return
     */
    public OA4MPResponse requestCert() {
        return requestCert((Identifier) null);
    }

    /**
     * A convenience method to do the {@link #requestCert()} call and create an asset with the given identifier. This
     * will throw an exception if there is no asset store configured.
     *
     * @param identifier
     * @return
     */
    public OA4MPResponse requestCert(Identifier identifier) {
        Map m = new HashMap();
        return requestCert(identifier, m);
    }

    public AssetProvider getAssetProvider() {
        return assetProvider;
    }

    public void setAssetProvider(AssetProvider assetProvider) {
        this.assetProvider = assetProvider;
    }

    AssetProvider assetProvider;

    /**
     * A convenience method that allows for a map of additional parameters.
     *
     * @param identifier
     * @param additionalParameters
     * @return
     */
    public OA4MPResponse requestCert(Identifier identifier, Map additionalParameters) {
        if (additionalParameters == null) {
            additionalParameters = new HashMap();
        }
        AssetProvider assetProvider = getEnvironment().getAssetProvider();
        Asset asset = null;
        if (identifier == null) {
            asset = assetProvider.get(false); // no id
        } else {
            asset = assetProvider.get(identifier);
        }

        OA4MPResponse response = requestCert(asset, additionalParameters);
        asset.setPrivateKey(response.getPrivateKey());
        asset.setRedirect(response.getRedirect());
        getAssetStore().save(asset);
        return response;
    }

    /**
     * Request a certificate from the user portal. This will also generate the private key and cert request. These
     * are not stored by this service. The additionalParameters argument are passed as key/value pairs
     * in the initial request
     * and are not otherwise processed.
     *
     * @return
     */
    public OA4MPResponse requestCert(Map additionalParameters) {
        return requestCert((Identifier) null, additionalParameters);
    }

    /**
     * Used in making a consistent base 64-based uri from a string.
     */
    protected String BASE64_URI_CAPUT = "b64:";

    protected Identifier makeb64Uri(String x) {
        Base64String b64 = new Base64String(x.getBytes());
        Identifier id = BasicIdentifier.newID(BASE64_URI_CAPUT + b64);
        return id;
    }


    long keypairExpiration = 0L;
    KeyPair keyPair = null;

    protected KeyPair getNextKeyPair() {
        if (keyPair == null || (getEnvironment().getKeypairLifetime() <= 0) || (keypairExpiration < System.currentTimeMillis())) {
            try {
                keyPair = KeyUtil.generateKeyPair();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }

            keypairExpiration = System.currentTimeMillis() + getEnvironment().getKeypairLifetime();
        }
        return keyPair;
    }


    protected OA4MPResponse requestCert(Asset asset, Map additionalParameters) {
        if (additionalParameters == null) {
            additionalParameters = new HashMap();
        }
        try {

            preRequestCert(asset, additionalParameters);

            OA4MPResponse mpdsResponse = new OA4MPResponse();
            mpdsResponse.setPrivateKey(asset.getPrivateKey());
            DelegationRequest daReq = new DelegationRequest();
            daReq.setParameters(additionalParameters);
            daReq.setClient(getEnvironment().getClient());
            daReq.setBaseUri(getEnvironment().getAuthorizationUri());
            DelegationResponse daResp = (DelegationResponse) getEnvironment().getDelegationService().process(daReq);
            if (daResp.getAuthorizationGrant() != null) {
                asset.setToken(BasicIdentifier.newID(daResp.getAuthorizationGrant().getToken()));
                if (asset.getIdentifier() == null) {
                    asset.setIdentifier(makeb64Uri(daResp.getAuthorizationGrant().getToken().toString()));
                }
            }
            String skin = getEnvironment().getSkin();
            String r = daResp.getRedirectUri().toString();
            if (skin != null) {
                r = r + "&" + SKIN_PARAMETER + "=" + skin;

            }
            // FIXME!! For OAuth 2, how do we introduce the skin parameter if there is no rewriting of the url before
            // getting forwarded to an Authz module? Might have to send it across in the initial call.
            mpdsResponse.setRedirect(URI.create(r));

            getAssetStore().save(asset);
            postRequestCert(asset, mpdsResponse);
            return mpdsResponse;
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Error generating request", e);
        }

    }


    /**
     * Retrieve the certificate chain from the server. This is done after the {@link #requestCert()} and
     * user authorization.
     *
     * @param tempToken
     * @param verifier
     * @return
     */
    public AssetResponse getCert(String tempToken, String verifier) {
        return getCert(tempToken, verifier, null);
    }


    /**
     * Performs the {@link #getCert(String, String)} call then updates the asset associated with
     * the given identifier. This throws an exception is there is no asset or if the asset store
     * is not enabled.
     *
     * @param tempToken
     * @param verifier
     * @param identifier
     * @return
     */
    public AssetResponse getCert(String tempToken, String verifier, Identifier identifier) {
        Asset asset = null;
        Identifier realId = null;

        if (identifier == null) {
            realId = makeb64Uri(tempToken); // failsafe. Should only happen if user never specifies an identifier
        } else {
            realId = identifier; // most common use case by far.
        }
        if (realId == null) {
            throw new IllegalArgumentException("Error: no identifier found for this transaction. Cannot retrieve asset.");
        }
        asset = getAssetStore().get(realId);
        if (asset == null && tempToken != null) {
            asset = getAssetStore().getByToken(BasicIdentifier.newID(tempToken));
        }
        if (asset == null) {
            // If the asset is still null nothing is found, so demunge any identifier and throw an exception.
            String currentID = tempToken == null ? realId.toString() : tempToken;
            throw new IllegalArgumentException("Error:No asset with the given identifier \"" + currentID + "\" found. " +
                    "You might need to clear your cookies and retry the entire request.");
        }
        AuthorizationGrant ag = getEnvironment().getTokenForge().getAuthorizationGrant(tempToken);
        Verifier v = null;
        if (verifier != null) {
            v = getEnvironment().getTokenForge().getVerifier(verifier);
        }
        return getCert(asset, ag, v);
    }

    /**
     * This creates the parameter map for the access token request. Send along anything specific to the
     * protocol in this map.
     *
     * @param asset
     * @param ag
     * @param v
     * @return
     */
    protected Map<String, String> getATParameters(Asset asset, AuthorizationGrant ag, Verifier v) {
        Map m = new HashMap();
        m.put(getEnvironment().getConstants().get(ClientEnvironment.CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        return m;
    }

    /**
     * This creates the parameter map for the certificate request. Send along anything specific to the protocol
     * in this map.
     *
     * @param asset
     * @return
     */
    protected Map<String, String> getAssetParameters(Asset asset) {
        Map m1 = new HashMap();
        m1.put(getEnvironment().getConstants().get(ClientEnvironment.CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        return m1;
    }

    /**
     * Does the actual work getting the cert.
     *
     * @param asset
     * @param ag
     * @param v
     * @return
     */
    protected AssetResponse getCert(Asset asset, AuthorizationGrant ag, Verifier v) {
        DelegatedAssetRequest dar = new DelegatedAssetRequest();
        dar.setAuthorizationGrant(ag);
        dar.setClient(getEnvironment().getClient());
        dar.setVerifier(v);
        dar.setParameters(getATParameters(asset, ag, v));

        Map<String, String> m1 = getAssetParameters(asset);
        preGetCert(asset, m1);
        dar.setAssetParameters(m1);

        DelegatedAssetResponse daResp = (DelegatedAssetResponse) getEnvironment().getDelegationService().process(dar);

        AssetResponse par = new AssetResponse();
        MyX509Certificates myX509Certificate = (MyX509Certificates) daResp.getProtectedAsset();
        par.setX509Certificates(myX509Certificate.getX509Certificates());
        par.setUsername(daResp.getAdditionalInformation().get("username"));
        postGetCert(asset, par);
        asset.setUsername(par.getUsername());
        asset.setCertificates(par.getX509Certificates());
        getEnvironment().getAssetStore().save(asset);
        return par;
    }

}
