package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.AbstractPayloadConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenClientConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ClientUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AccessTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.RefreshTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.BaseClient;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Scopes;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.OA2ClientScopes;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfiguration;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
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
    // CIL-1586. Have a default "use the server value" and explicitly use it.
    public static final long USE_SERVER_DEFAULT = -1L;
    public static final long DISABLE_REFRESH_TOKENS = 0L;
    @Override
    public OA2Client clone() {
        OA2Client client = new OA2Client(getIdentifier());
        populateClone(client);
        return client;
    }

    long maxATLifetime = USE_SERVER_DEFAULT;
    long maxRTLifetime = USE_SERVER_DEFAULT;

    /**
     * The maximum lifetime, if different from the server max, for this client. Note that once set,
     * no AT lifetime can exceed this. Set to <= 0 to use the server max. as the client max.
     *
     * @return
     */

    public long getMaxATLifetime() {
        return maxATLifetime;
    }

    public void setMaxATLifetime(long maxATLifetime) {
        this.maxATLifetime = maxATLifetime;
    }

    /**
     * The maximum lifetime, if different from the server max, for this client. Note that once set,
     * no RT lifetime can exceed this. Set to <= 0 to use the server max. as the client max.
     *
     * @return
     */
    public long getMaxRTLifetime() {
        return maxRTLifetime;
    }

    public void setMaxRTLifetime(long maxRTLifetime) {
        this.maxRTLifetime = maxRTLifetime;
    }

    @Override
    protected void
    populateClone(BaseClient c) {
        OA2Client client = (OA2Client) c;
        super.populateClone(client);
        client.setCallbackURIs(getCallbackURIs());
        client.setConfig(getConfig());
        client.setForwardScopesToProxy(isForwardScopesToProxy());
        client.setIssuer(getIssuer());
        client.setLdaps(getLdaps());
        client.setMaxATLifetime(getMaxATLifetime());
        client.setMaxRTLifetime(getMaxRTLifetime());
        client.setPrototypes(getPrototypes());
        client.setProxyClaimsList(getProxyClaimsList());
        client.setProxyRequestScopes(getProxyRequestScopes());
        // https://github.com/rcauth-eu/OA4MP/commit/38f0f2ca7e2ef5609006794b96485ae1a7e00ff0
        client.setPublicClient(isPublicClient());
        client.setRawConfig(getRawConfig());
        client.setRtLifetime(getRtLifetime());
        client.setScopes(getScopes());
        client.setSignTokens(isSignTokens());
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    String comment;

    public List<Identifier> getPrototypes() {
        if (prototypes == null) {
            prototypes = new ArrayList<>();
        }
        return prototypes;
    }

    public void setPrototypes(List<Identifier> prototypes) {
        this.prototypes = prototypes;
    }

    List<Identifier> prototypes = null;

    public boolean hasPrototypes() {
        return !(prototypes == null || prototypes.isEmpty());
    }

    public boolean isErsatzClient() {
        return ersatzClient;
    }

    public void setErsatzClient(boolean ersatzClient) {
        this.ersatzClient = ersatzClient;
    }

    boolean ersatzClient = false;

    /**
     * If the ersatz client should simply extend all provisioners. This means you do not have to set the
     * {@link #setPrototypes(List)} for this object. If you do set it, those will be processed first
     * then the provisioners.
     *
     * @return
     */
    public boolean isExtendsProvisioners() {
        return extendsProvisioners;
    }

    public void setExtendsProvisioners(boolean extendsProvisioners) {
        this.extendsProvisioners = extendsProvisioners;
    }

    boolean extendsProvisioners = false;

    public boolean isSkipServerScripts() {
        return skipServerScripts;
    }

    public void setSkipServerScripts(boolean skipServerScripts) {
        this.skipServerScripts = skipServerScripts;
    }

    boolean skipServerScripts = false;

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

    long rtLifetime = USE_SERVER_DEFAULT;

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

    long atLifetime = USE_SERVER_DEFAULT;

    /**
     * This returns whether or not this client is configured to return refresh tokens.
     * Zero means no refresh tokens, positive is the lifetime, negative {@link #USE_SERVER_DEFAULT}
     * means to use the server default.
     * Disabled means the lifetime is set to zero. See also {@link #getMaxRTLifetime()}
     *
     * @return
     */
    public boolean isRTLifetimeEnabled() {
        return 0 < rtLifetime;
    }

    public Collection<String> getAudience() {
        return audience;
    }

    public void setAudience(Collection<String> audience) {
        this.audience = audience;
    }

    Collection<String> audience;

    public List<URI> getResource() {
        return resource;
    }

    public void setResource(List<URI> resource) {
        this.resource = resource;
    }

    List<URI> resource;

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
    protected String ID_TOKENS_KEY = "identity";

    protected boolean hasPayloadConfig(String root, String path) {
        return containsKey(getConfig(), root, path);
    }

    protected AbstractPayloadConfig setupPayloadConfig(AbstractPayloadConfig pc, String root, String path) {
        if (hasDriverConfig()) {
            OA2ClientUtils.setupDriverPayloadConfig(pc, this);
        }
        if (hasPayloadConfig(root, path)) {
            pc.fromJSON(getJSONObject(getConfig(), root, path));
        }
        return pc;
    }

    protected void setPayloadConfig(AbstractPayloadConfig apc, String root, String path) {
        set(apc.toJSON(), root, path);
    }

    public boolean hasAccessTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, ACCESS_TOKENS_KEY) || hasDriverConfig();
    }

    public AccessTokenConfig getAccessTokensConfig() {
        AccessTokenConfig atConfig = new AccessTokenConfig(); // empty
        return (AccessTokenConfig) setupPayloadConfig(atConfig, TOKENS_KEY, ACCESS_TOKENS_KEY);
    }

    private Object setupDriverPayloadConfig(AccessTokenConfig atConfig, JSONObject config) {
        return null;
    }

    public boolean hasDriverConfig() {
        return getConfig().containsKey(QDLRuntimeEngine.CONFIG_TAG);
    }

    public void setAccessTokenConfig(AccessTokenConfig cfg) {
        setPayloadConfig(cfg, TOKENS_KEY, ACCESS_TOKENS_KEY);
    }


    // Refresh token & config
    public void setRefreshTokensConfig(RefreshTokenConfig refreshTokenConfig) {
        setPayloadConfig(refreshTokenConfig, TOKENS_KEY, REFRESH_TOKENS_KEY);
    }

    public boolean hasRefreshTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, REFRESH_TOKENS_KEY) || hasDriverConfig();
    }

    public RefreshTokenConfig getRefreshTokensConfig() {
        RefreshTokenConfig refreshTokenClientConfig = new RefreshTokenConfig(); // empty
        return (RefreshTokenConfig) setupPayloadConfig(refreshTokenClientConfig, TOKENS_KEY, REFRESH_TOKENS_KEY);

    }

    public boolean hasIDTokenConfig() {
        return hasPayloadConfig(TOKENS_KEY, ID_TOKENS_KEY) || hasDriverConfig();
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
     *
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

    public static String CLIENT_COMMENT_TAG = "comment";

    public void setComment(List<String> comments) {
        setNamedList(oa4mp_attributes, CLIENT_COMMENT_TAG, comments);
    }

    public List<String> getComment() {
        return getNamedList(oa4mp_attributes, CLIENT_COMMENT_TAG);
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
     * See the {@link edu.uiuc.ncsa.oa4mp.delegation.oa2.server.scripts.ClientJSONConfigUtil}
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

    public void setExtendedAttributes(JSONObject eas) {
        this.extended_attributes = eas;
    }

    protected JSONObject extended_attributes;

    public boolean hasExtendedAttributes() {
        return extended_attributes != null;
    }

    @Override
    public String toString() {
        String x = super.toString();
        x = x.substring(0, x.lastIndexOf("]"));
        x = x + "scopes=" + ((getScopes() == null) ? "[]" : getScopes().toString());
        x = x + ",callbacks=" + (getCallbackURIs() == null ? "[]" : getCallbackURIs().toString());
        x = x + ",issuer=" + getIssuer();
        x = x + ",is public?=" + isPublicClient();
        // https://github.com/rcauth-eu/OA4MP/commit/bf2ea509aebbf90da74ed529e701a0db44bcac96 remove redundant printing of rt lifetime
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

    public boolean hasScript() {
        boolean rc = false;
        rc = rc || hasIDTokenConfig() && !getIDTokenConfig().getScriptSet().isEmpty();
        rc = rc || hasAccessTokenConfig() && !getAccessTokensConfig().getScriptSet().isEmpty();
        rc = rc || hasRefreshTokenConfig() && !getRefreshTokensConfig().getScriptSet().isEmpty();

        return rc;
    }

    long dfLifetime = USE_SERVER_DEFAULT; // device flow configured lifetime.

    public long getDfLifetime() {
        return dfLifetime;
    }

    public void setDfLifetime(long dfLifetime) {
        this.dfLifetime = dfLifetime;
    }

    public long getDfInterval() {
        return dfInterval;
    }

    public void setDfInterval(long dfInterval) {
        this.dfInterval = dfInterval;
    }

    long dfInterval = USE_SERVER_DEFAULT; // device flow interval in ms

    /**
     * This is a string that tells what claims <b>in addition to the subject</b> to take from
     * the proxy claims. Default is just to take the subject. Options are
     * <ul>
     *     <li>(empty) - default = just take the sub claim</li>
     *     <li>[*] - all</li>
     *     <li>[c0, c1, c2,...] - a list</li>
     * </ul>
     *
     * @return
     */
    public Collection<String> getProxyClaimsList() {
        return proxyClaimsList;
    }

    public void setProxyClaimsList(Collection<String> proxyClaimsList) {
        this.proxyClaimsList = proxyClaimsList;
    }

    Collection<String> proxyClaimsList = new ArrayList<>();

    /**
     * If the client needs a subset of scopes from the proxy, they go here.
     *
     * @return
     */
    // CIL-1584
    public Collection<String> getProxyRequestScopes() {
        if(proxyRequestScopes == null){
            proxyRequestScopes = new ArrayList<>();
            proxyRequestScopes.add("*"); // default is all of them
        }
        return proxyRequestScopes;
    }

    public void setProxyRequestScopes(Collection<String> proxyRequestScopes) {
        this.proxyRequestScopes = proxyRequestScopes;
    }

    Collection<String> proxyRequestScopes = new ArrayList<>();

    public boolean hasRequestScopes() {
        return proxyRequestScopes != null && !proxyRequestScopes.isEmpty();
    }

    // CIL-1584
    public boolean isForwardScopesToProxy() {
        return forwardScopesToProxy;
    }

    public void setForwardScopesToProxy(boolean forwardScopesToProxy) {
        this.forwardScopesToProxy = forwardScopesToProxy;
    }

    boolean forwardScopesToProxy = false;

    public long getRtGracePeriod() {
        return rtGracePeriod;
    }

    public void setRtGracePeriod(long rtGracePeriod) {
        this.rtGracePeriod = rtGracePeriod;
    }

    long rtGracePeriod = OA2ConfigurationLoader.REFRESH_TOKEN_GRACE_PERIOD_USE_SERVER_DEFAULT;

    /**
     * If this is an ersatz client, should it inherit the id token of its provisioner
     * when forking the flow? If true, then yes, if false, then no.
     * <p>There are many times when the ersatz client needs some information in the
     * id token of the provisioner (such as job id or other accounting information) and
     * times when no information should be shared. Since this is generally undecideable,
     * a flag si supplied.</p>
     * @return
     */
    public boolean isErsatzInheritIDToken() {
        return ersatzInheritIDToken;
    }

    public void setErsatzInheritIDToken(boolean ersatzInheritIDToken) {
        this.ersatzInheritIDToken = ersatzInheritIDToken;
    }

    boolean ersatzInheritIDToken = true;

}

