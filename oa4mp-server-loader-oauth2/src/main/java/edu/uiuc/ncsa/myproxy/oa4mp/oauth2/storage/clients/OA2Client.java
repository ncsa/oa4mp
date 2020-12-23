package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenClientConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AccessTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.RefreshTokenConfig;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2ClientScopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;
import static edu.uiuc.ncsa.security.util.json.MyJPathUtil.*;

/**
 * OAuth2 Open ID connect protocol requires that sites register callback uris and that incoming requests
 * must include a callback that matches one of the registered ones.
 * <p>Created by Jeff Gaynor<br>
 * on 3/14/14 at  11:04 AM
 */
public class OA2Client extends Client implements OA2ClientScopes {
    @Override
    public OA2Client clone() {
        OA2Client client = new OA2Client(getIdentifier());
        populateClone(client);
        return client;
    }

    @Override
    protected void populateClone(BaseClient c) {
        OA2Client client = (OA2Client) c;
        super.populateClone(client);
        client.setRtLifetime(getRtLifetime());
        client.setCallbackURIs(getCallbackURIs());
        client.setScopes(getScopes());
        client.setLdaps(getLdaps());
        client.setConfig(getConfig());
        client.setRawConfig(getRawConfig());
        client.setIssuer(getIssuer());
        client.setSignTokens(isSignTokens());
    }

    public boolean isPublicClient() {
        return publicClient;
    }

    public boolean isOIDCClient() {
        return getScopes().contains(OA2Scopes.SCOPE_OPENID);
    }

    public void setPublicClient(boolean publicClient) {
        this.publicClient = publicClient;
    }

    protected boolean publicClient = false;

    public boolean isSignTokens() {
        return signTokens;
    }

    public void setSignTokens(boolean signTokens) {
        this.signTokens = signTokens;
    }

    boolean signTokens = true; // new default as of version 3.4. Fixes CIL-405
    String issuer = null;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public OA2Client(Identifier identifier) {
        super(identifier);
    }

    public Collection<String> getCallbackURIs() {
        return callbackURIs;
    }

    public void setCallbackURIs(Collection<String> callbackURIs) {
        this.callbackURIs = callbackURIs;
    }

    Collection<String> callbackURIs = new LinkedList<>();

    long rtLifetime = 0L;

    public long getRtLifetime() {
        return rtLifetime;
    }

    public void setRtLifetime(long rtLifetime) {
        this.rtLifetime = rtLifetime;
    }

    public long getAtLifetime() {
        return atLifetime;
    }

    public void setAtLifetime(long atLifetime) {
        this.atLifetime = atLifetime;
    }

    long atLifetime = -1L;

    /**
     * This returns whether or not this client is configured to return refresh tokens.
     *
     * @return
     */
    public boolean isRTLifetimeEnabled() {
        return 0 < rtLifetime;
    }

    public Collection<String> getScopes() {
        return scopes;
    }

    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    Collection<String> scopes = new LinkedList<>();

    public Collection<LDAPConfiguration> getLdaps() {
        return ldaps;
    }

    public void setLdaps(Collection<LDAPConfiguration> ldaps) {
        this.ldaps = ldaps;
    }

    Collection<LDAPConfiguration> ldaps;
    String extendedAttributesEnabledKey = "extendedAttributesEnabled";
    protected String xoauth_attributes = "xoauth_attributes";
    protected String oa4mp_attributes = "oa4mp_attributes";
    protected String oidc_cm_attributes = "oidc-cm_attributes";
    protected String TOKENS_KEY = "/tokens";
    protected String ACCESS_TOKENS_KEY = "access";
    protected String REFRESH_TOKENS_KEY = "refresh";
    protected String WLCG_TOKENS_KEY = "wlcg_token";
    protected String ID_TOKENS_KEY = "identity";

    protected boolean hasPayloadConfig(String root, String path) {
        return containsKey(getConfig(), root, path);
    }

    protected AbstractPayloadConfig setupPayloadConfig(AbstractPayloadConfig pc, String root, String path) {
        if (hasPayloadConfig(root, path)) {
            pc.fromJSON(getJSONObject(getConfig(), root, path));
        }
        return pc;
    }

    protected void setPayloadConfig(AbstractPayloadConfig apc, String root, String path) {
        set(apc.toJSON(), root, path);
    }

    public boolean hasAccessTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, ACCESS_TOKENS_KEY);
    }

    public AccessTokenConfig getAccessTokensConfig() {
        AccessTokenConfig atConfig = new AccessTokenConfig(); // empty
        return (AccessTokenConfig) setupPayloadConfig(atConfig, TOKENS_KEY, ACCESS_TOKENS_KEY);
    }

    public void setAccessToken(AccessTokenConfig cfg) {
        //set(getConfig(), TOKENS_KEY, ACCESS_TOKENS_KEY, cfg.toJSON());
        setPayloadConfig(cfg, TOKENS_KEY, ACCESS_TOKENS_KEY);
    }


    // Refresh token & config
    public void setRefreshTokensConfig(RefreshTokenConfig refreshTokenConfig) {
        setPayloadConfig(refreshTokenConfig, TOKENS_KEY, REFRESH_TOKENS_KEY);
    }

    public boolean hasRefreshTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, REFRESH_TOKENS_KEY);
    }

    public RefreshTokenConfig getRefreshTokensConfig() {
        RefreshTokenConfig refreshTokenClientConfig = new RefreshTokenConfig(); // empty
        return (RefreshTokenConfig) setupPayloadConfig(refreshTokenClientConfig, TOKENS_KEY, REFRESH_TOKENS_KEY);

    }

    public boolean hasIDTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, ID_TOKENS_KEY);
    }

    public IDTokenClientConfig getIDTokenConfig() {
        IDTokenClientConfig c = new IDTokenClientConfig();
        return (IDTokenClientConfig) setupPayloadConfig(c, TOKENS_KEY, ID_TOKENS_KEY);
    }

    public void setIDTokenConfig(IDTokenClientConfig idTokenClientConfig) {
        setPayloadConfig(idTokenClientConfig, TOKENS_KEY, ID_TOKENS_KEY);
    }

    protected JSONObject getNamedAttributes(String name) {
        if (getExtendedAttributes().containsKey(name)) {
            return getExtendedAttributes().getJSONObject(name);
        }
        JSONObject jsonObject = new JSONObject();
        getExtendedAttributes().put(name, jsonObject);
        return getExtendedAttributes().getJSONObject(name); // Because the JSON library copies the values, it does not pass by reference!
    }

    protected void setNamedAttributes(String name, JSONObject jsonObject) {
        getExtendedAttributes().put(name, jsonObject);
    }

    public boolean hasOIDC_CM_Attributes() {
        return getNamedAttributes(oidc_cm_attributes) != null && !getNamedAttributes(oidc_cm_attributes).isEmpty();
    }

    public JSONObject getOIDC_CM_Attributes() {
        return getNamedAttributes(oidc_cm_attributes);
    }

    public void setOIDC_CM_attributes(JSONObject attr) {
        setNamedAttributes(oidc_cm_attributes, attr);
    }

    public void removeOIDC_CM_Attributes() {
        getExtendedAttributes().remove(oidc_cm_attributes);
    }

    protected JSONObject getOA4MPAttributes() {
        return getNamedAttributes(oa4mp_attributes);
    }

    protected JSONObject getXOAuthExtendedAttributes() {
        return getNamedAttributes(xoauth_attributes);
    }

    /**
     * Extended attributes refers to allowing the client pass in NS qualified additional parameters
     * in the request. Normally, these are ignored (as per spec). However, we can accept additional
     * parameters (as per spec too), so if this is set to true, then those prefixed correctly will
     * be added to the transaction for later processing. The default is false for this option.
     * <h3>Note</h3>
     * These reside in the JSON configuration as part of a separate extra attributes object.
     * So in the configuration you should have something like
     * <pre>
     *     {"cfg":["comments"],
     *       "extraAttributes":{"extendedAttributesEnabled":true},
     *       ... other stuff.
     *     }
     * </pre>
     *
     * @return
     */
    public boolean hasExtendedAttributeSupport() {
        Boolean b = (Boolean) getNamedProperty(oa4mp_attributes, extendedAttributesEnabledKey);
        if (b == null) {
            return false;
        }
        return b;
    }

    public void setExtendedAttributeSupport(boolean b) {
        setNamedProperty(oa4mp_attributes, extendedAttributesEnabledKey, b);
    }

    boolean strictScopes = true;


    /**
     * Strict scopes means that the list of scopes must match exactly for the given client.
     * Typically this is <code>false</code> for WLCG and other clients that can pass in arbitrary
     * scopes.
     * @return
     */
    public boolean useStrictScopes() {
        return strictScopes;
    }

    public void setStrictscopes(boolean newValue) {
        strictScopes = newValue;
    }

    protected Object getNamedProperty(String component, String key) {
        if (getNamedAttributes(component).containsKey(key)) {
            return getNamedAttributes(component).get(key);
        }
        return null;
    }

    protected void setNamedProperty(String component, String key, Object property) {
        getNamedAttributes(component).put(key, property);  // warning the JSON library we use copies objects rather than setting them.
    }

    protected List<String> getNamedList(String component, String key) {
        if (getNamedAttributes(component).containsKey(key)) {
            return getNamedAttributes(component).getJSONArray(key);
        }
        return new JSONArray();

    }

    protected void setNamedList(String component, String key, List<String> list) {
        JSONArray ja = null;
        if (list instanceof JSONArray) {
            ja = (JSONArray) list;
        } else {
            ja = new JSONArray();
            ja.addAll(list);
        }
        getNamedAttributes(component).put(key, ja);
    }

    public List<String> getGrantTypes() {
        return getNamedList(xoauth_attributes, OA2Constants.GRANT_TYPE);
    }

    public void setGrantTypes(List<String> grantTypes) {
        setNamedList(xoauth_attributes, OA2Constants.GRANT_TYPE, grantTypes);
    }

    public List<String> getResponseTypes() {
        return getNamedList(xoauth_attributes, OA2Constants.RESPONSE_TYPE);
    }

    public void setResponseTypes(List<String> responseTypes) {
        setNamedList(xoauth_attributes, OA2Constants.RESPONSE_TYPE, responseTypes);
    }

    /**
     * The JSON configuration object.
     * The format is as follows:
     * <pre>
     * {
     *   "config":"comment",
     *   "claims":{"sources":[JSON],
     *             "logic":[JSON],
     *             "source_config":[JSON],
     *             "processing":[JSON]},
     *    "sci_tokens":{"usernameClaimKey":"value", "templates":[...], "qdl":{...}},
     *    "id_tokens":{"qdl":{...}},
     *    "wlcg_token":{"qdl":{...}},
     *    "isSaved":true|false
     * }
     * </pre>
     * <p>Note that the "claims" entry is deprecated and mostly refers to the old JFunctor scripting. Don't use in new
     * configurations. The isSaved entry too relates to JFunctors and is ignored by all other components.</p>
     * <p>
     * See the {@link edu.uiuc.ncsa.security.oauth_2_0.server.scripts.ClientJSONConfigUtil}
     * JSON may be either a single JSON object or an array of them. If a single, it is
     * converted to an array of a single object before processing.
     * <p>
     * As of now (version 4.3), the claims block which is simple functor scripting is
     * deprecated in favor of the new qdl block.
     * JSON may be a logic block  (which consists of various JSON functors.
     *
     * <pre>
     * {
     *   "$if":conditionals,
     *   "$then":"actions",
     *   "$else":"other actions"
     * }
     * </pre>
     * <p>
     * conditionals, actions and other actions are JSON objects or arrays of them as well.
     * Note that the conditional must be a functor that evaluates to a logical value.
     *
     * @return
     */
    public JSONObject getConfig() {
        if (jsonConfig == null && !StringUtils.isTrivial(config)) {
            throw new IllegalStateException("Error: JSON configuration was not initialized.");
        }
        return jsonConfig;
    }

    public boolean hasConfig() {
        return config != null;
    }

    public void setConfig(JSONObject config) {
        this.jsonConfig = config;
    }

    protected String config;
    protected JSONObject jsonConfig;

    public void setRawConfig(String rawConfig) {
        config = rawConfig;
    }

    public String getRawConfig() {
        return config;
    }

    /**
     * Extended attributes base call. The {@link #getConfig()} gets user-facing configuration, like scripts
     * and maybe other things not related to OAuth. Extended attributes  are for
     * core configuration such as more grant types
     * and such that come from specifications and are generally not open to change. The reason for this is
     * simple: as OA4MP evolves, more and more attributes must be managed and rather than keep adding more
     * database columns (and also have to update other store types too, with all the management that implies),
     * just have a central place
     * and leave all logic for them otherwise in software.   Setters and getters are added to this class which
     * store their information in a JSON blob.
     * <h2>Structure</h2>
     * The structure is a flat list of attributes as:
     * <pre>
     *     {
     *      "xoauth_attributes":{"grant_type":[....},  <-- attributes for OAuth
     *      "oa4mp_attributes":{"foo":"bar",...}       <-- attributes relating to OA4MP
     *      "oidc-cm":{"x":"y",...}                    <-- unused attributes RFC7951, so we have them
     *     ... etc
     *     }
     * </pre>
     *
     * @return
     */
    public JSONObject getExtendedAttributes() {
        if (extended_attributes == null) {
            extended_attributes = new JSONObject();
        }
        return extended_attributes;
    }

    protected void setExtendedAttributes(JSONObject eas) {
        this.extended_attributes = eas;
    }

    protected JSONObject extended_attributes;

    protected boolean hasExtendedAttributes() {
        return extended_attributes != null;
    }

    @Override
    public String toString() {
        String x = super.toString();
        x = x.substring(0, x.lastIndexOf("]"));
        x = x + "scopes=" + ((getScopes() == null) ? "[]" : getScopes().toString());
        x = x + ",callbacks=" + (getCallbackURIs() == null ? "[]" : getCallbackURIs().toString());
        x = x + ",refresh token lifetime=" + getRtLifetime();
        x = x + ",issuer=" + getIssuer();
        x = x + ",is public?=" + isPublicClient();
        x = x + ",rt lifetime=" + getRtLifetime();
        x = x + ",rt lifetime enabled?=" + isRTLifetimeEnabled();
        x = x + ",sign ID tokens?=" + isSignTokens();
        return x + "]";
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof OA2Client)) return false;
        OA2Client c = (OA2Client) obj;
        if (getRtLifetime() != c.getRtLifetime()) return false;
        if (!checkEquals(getIssuer(), c.getIssuer())) return false;

        if (getScopes().size() != c.getScopes().size()) return false;
        for (String x : getScopes()) {
            if (!c.getScopes().contains(x)) return false;
        }

        if (getCallbackURIs().size() != c.getCallbackURIs().size()) return false;
        for (String x : getCallbackURIs()) {
            if (!c.getCallbackURIs().contains(x)) return false;
        }
        if (isSignTokens() != c.isSignTokens()) return false;
        if (isPublicClient() != c.isPublicClient()) return false;
        // note that at this point neither the LDAP nor configuration are checked for equality since there
        // is no well defined way to tell when two JSON object describe the same information -- serialization
        // is even inconsistent by different libraries.
        return super.equals(obj);
    }

    public static void main(String[] args) {
        OA2Client client = new OA2Client(BasicIdentifier.randomID()); // just need one
        client.setExtendedAttributeSupport(true);
        List<String> gt = new ArrayList<>();
        gt.add("gt_foo");
        gt.add("gt_bar");
        client.setGrantTypes(gt);
        List<String> rst = new ArrayList<>();
        rst.add("rst_1");
        rst.add("rst_2");
        client.setResponseTypes(rst);
        System.out.println(client.getExtendedAttributes().toString(2));
    }

}

