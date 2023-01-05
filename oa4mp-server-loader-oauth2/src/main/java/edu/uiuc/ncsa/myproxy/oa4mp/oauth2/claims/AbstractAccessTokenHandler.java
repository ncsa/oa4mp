package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AccessTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationPath;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationTemplate;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationTemplates;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.AccessTokenHandlerInterface;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.JWTUtil2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8693Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ScopeTemplateUtil.doCompareTemplates;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.ScopeTemplateUtil.replaceTemplate;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.*;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;

/**
 * Only create an access token handler if you need some special handling, otherwise the
 * default simple token will be used.
 * <p>Created by Jeff Gaynor<br>
 * on 7/21/20 at  2:50 PM
 */
public class AbstractAccessTokenHandler extends AbstractPayloadHandler implements AccessTokenHandlerInterface {
    public static final String AT_DEFAULT_HANDLER_TYPE = "default";
    public static final String AT_BASIC_HANDLER_TYPE = "access";

    public AbstractAccessTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
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

    JSONObject atData;

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
        super.handleResponse(resp);
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                setClaims((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                setExtendedAttributes((JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES));
                setAtData((JSONObject) resp.getReturnedValues().get(SRE_REQ_ACCESS_TOKEN));
                return;
            case RC_NOT_RUN:
                return;
        }
    }

    @Override
    public void checkClaims() throws Throwable {

    }

    /**
     * Templates are of the format
     * <pre>
     *     [{"aud":audience,
     *     [{"op":X0, "path":P0},
     *      {"op":X1, "path":P1},...}]
     *     ]
     * </pre>
     */
    public String resolveTemplates(boolean isQuery) {
        // Returning a null means that this was skipped or did not execute.
        if (!transaction.getFlowStates().at_do_templates) {
            // This implies that, e.g. in a script, template processing was explicitly
            // stopped. Normally this implies that there are templates, but in some case,
            // a script sets all of the requested scopes rather than relying on the template mechanism,.
            return null;
        }
        AuthorizationTemplates templates = getATConfig().getTemplates();
        if (templates.size() == 0) {
            return null; // nix to do
        }
        Collection<String> requestedAudience = transaction.getAudience();
        // check for audiences.
        if (requestedAudience == null || requestedAudience.isEmpty()) {

            switch (getATConfig().getAudience().size()) {
                case 0:
                    // no audiences configured and none requested.
                    throw new IllegalStateException("Error: The client has no configured audiences and none were requested. Cannot resolve scopes.");
                case 1:
                    // no audience requested and a single one is configured. Use that.
                    if (requestedAudience == null) {
                        requestedAudience = new ArrayList<>();
                    }
                    requestedAudience.add(getATConfig().getAudience().get(0));
                    break;
                default:
                    // no audiences any place, requested or configured.
                    throw new IllegalStateException("Error: The client is configured with multiple audiences, but none were requested. Cannot resolve scopes.");
            }
        }
        Map<String, List<String>> groupMap = new HashMap<>();

        /*
          Manual testing of groups. This lets me turn on groups to emulate a more complex
          testing environment. See the note in claims-handler-testing.txt

        Groups gg = new Groups();
        GroupElement groupElement = new GroupElement("all-access", 42);
        gg.put(groupElement);
        getClaims().put("memberOf", gg.toJSON());

        gg = new Groups();
        groupElement = new GroupElement("other-access", 43);
        gg.put(groupElement);
        getClaims().put("otherMemberOf", gg.toJSON());
        */
        Map claimsNoGroups = new HashMap();
        for (Object claimKey : getClaims().keySet()) {
            Object claim = getClaims().get(claimKey);
            // Only groups are allowed to be embedded arrays in claims.
            if (claim instanceof JSONArray) {
                List<String> groupKeys = new ArrayList<>();  // list of groups in the current claims for this user

                JSONArray array = (JSONArray) claim;
                for (int i = 0; i < array.size(); i++) {
                    JSONObject jo = array.getJSONObject(i);
                    if (jo.containsKey(Groups.GROUP_ENTRY_NAME)) {
                        groupKeys.add(jo.getString(Groups.GROUP_ENTRY_NAME));
                    }
                }
                if (!groupKeys.isEmpty()) {
                    groupMap.put(claimKey.toString(), groupKeys);
                }
            } else {
                claimsNoGroups.put(claimKey, claim);
            }
        }
        // So we have groups (if any) and we have target audiences (at least one, perhaps a default).
        // Next up is we have to look at all templates stored by audience and do the appropriate replacement
        // If the replaced version is one of the requested scopes, add it to the computedScopes to get returned.
        // If not, ignore it.
        Set<String> computedScopes = new HashSet<>(); // makes sure there are unique scopes.

        for (String aud : requestedAudience) {
            if (!templates.containsKey(aud)) {
                throw new IllegalStateException("Error: The requested audience \"" + aud + "\" is not valid for this client. Cannot resolve scopes.");
            }
            AuthorizationTemplate template = templates.get(aud);
            for (AuthorizationPath authorizationPath : template.getPaths()) {
                List<String> z = replaceTemplate(authorizationPath.toPath(), groupMap, claimsNoGroups);
                computedScopes.addAll(z);
            }
        }
        // Scorecard: we have all the templates resolved for this resource/audience.
        // The question is what do we return?
        // This has the most recent exchange requests in it any of which may be empty.
        Collection<String> actualScopes;
        TXRecord txRecord = getPhCfg().getTxRecord();
        // Have to split the computed scopes into their uri and non-uri types.
        // E.g. if a scope is like compute.cancel it should not be processed as a template later.
        // Take them out here. Have to avoid concurrent modification exception, so stash them
        Collection<String> relativeScopes = new ArrayList<>();


        Collection<String> requestedScopes = (txRecord != null && txRecord.hasScopes()) ? txRecord.getScopes() : transaction.getScopes();
        Collection<String> badRequests = new ArrayList<>();
        Collection<String> relativeRequests = new ArrayList<>();
        /*
         * And for the next bit, if a capability is allowed like compute.submit
         * and the user tries to overload it to, e.g. compute.submit:/etc/certs
         * Do not assert the capability.
         *
         */
        for (String x : computedScopes) {
            if (!x.contains(":")) {
                if (requestedScopes.contains(x)) {
                    relativeRequests.add(x);
                } else {
                    for (String bad : requestedScopes) {
                        if (bad.startsWith(x + ":")) {
                            badRequests.add(bad);
                        }
                    }
                }
                relativeScopes.add(x);
            }

        }
        computedScopes.removeAll(relativeScopes);
        requestedScopes.remove(badRequests);

        /*

            If there is a token exchange record, then this is being invoked as part of a token
            exchange. In that case, any supplied scopes are used and the templates are used as
            super-paths.
        */

        actualScopes = doCompareTemplates(computedScopes,
                requestedScopes,
                isQuery);


        actualScopes.addAll(relativeRequests); // add back in relative computed scopes.
        // now we convert to a scope string.
        String s = "";
        boolean firstPass = true;
        for (String x : actualScopes) {
            if (firstPass) {
                firstPass = false;
                s = x;
            } else {
                s = s + " " + x;
            }
        }
        if (isTrivial(s)) {
            return null;
        }
        return s;

    }


    /**
     * Convenience to peel off the {@link AccessTokenConfig} from the handler config and return it.
     *
     * @return
     */
    protected AccessTokenConfig getATConfig() {
        return (AccessTokenConfig) getPhCfg().getClientConfig();
    }

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return new ArrayList<>();
    }

    public void finish(boolean doTemplates, boolean isQuery) throws Throwable {
        /*
          Make SURE the JTI gets set or token exchange, user info etc. will never work.
         */
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(transaction.getOA2Client());
        debugger.trace(this, "starting AT handler finish with transaction =" + transaction.summary());
        JSONObject atData = getAtData();
        if (getPhCfg().hasTXRecord()) {
            // Fixes CIL-971
            TXRecord txRecord = getPhCfg().getTxRecord();
            if (RFC8693Constants.ACCESS_TOKEN_TYPE.equals(txRecord.getTokenType())) {
                atData.put(JWT_ID, txRecord.getIdentifierString());
            }
        } else {
            debugger.trace(this, "update condition");
            if (transaction.getAccessToken() != null) {
                atData.put(JWT_ID, transaction.getAccessToken().getToken());
                debugger.trace(this, "update condition: TRUE, at=" + atData.get(JWT_ID));
            }
        }
        if (doTemplates) {
            String scopes = resolveTemplates(isQuery);
            if (scopes != null) {
                atData.put(OA2Constants.SCOPE, scopes);
            }
        }
        // AT Data is in seconds, as per spec!
        long proposedLifetime = (atData.getLong(EXPIRATION) - atData.getLong(ISSUED_AT)) * 1000;
        if (proposedLifetime <= 0) {
            proposedLifetime = transaction.getMaxAtLifetime();
        } else {
            proposedLifetime = Math.min(proposedLifetime, transaction.getMaxAtLifetime());
        }
        atData.put(EXPIRATION, (atData.getLong(ISSUED_AT) * 1000 + proposedLifetime) / 1000);
        if (!atData.containsKey(ISSUER)) {
            atData.put(ISSUER, transaction.getUserMetaData().getString(ISSUER));
        }

        if (!atData.containsKey(SUBJECT)) {
            // If the subject has not been set some place else, see if it is configured in the
            // client directly. If it is not configured there, there will be no subject
            // in this token.
            if (getATConfig().hasSubject()) {
                String newSubject = TemplateUtil.replaceAll(getATConfig().getSubject(), atData);
                atData.put(SUBJECT, newSubject);
            } else {
                // absolute last place option is to set it to the same subject as the
                // user. About half the time this works.
                atData.put(SUBJECT, transaction.getUserMetaData().getString(SUBJECT));
            }
        }
        
        doServerVariables(atData);
        setAtData(atData);
        transaction.setAccessTokenLifetime(proposedLifetime);
    }


    @Override
    public void finish(String execPhase) throws Throwable {
        boolean isQuery = false;
        switch (execPhase) {
            case SRE_PRE_AUTH:
            case SRE_POST_AUTH:
            case SRE_EXEC_INIT:
            case SRE_PRE_AT:
            case SRE_POST_AT:
                isQuery = true;
                break;
            default:
                // This covers refreshes and exchanges.
                isQuery = false;
        }
        finish(true, isQuery);
    }

    public AccessToken getSignedAT(JSONWebKey key) {
        return getSignedAT(key, JWTUtil2.DEFAULT_TYPE);
    }

    /**
     * Gets the AT data object (which has all the claims in it) and returns a signed access token.
     * This does <b>not</b> set the access token in the transaction but leaves up to the calling
     * application what to do, since different tokens have different contracts.
     *
     * @return
     */
    @Override
    public AccessToken getSignedAT(JSONWebKey key, String headerType) {
        if (key == null) {
            oa2se.warn("Error: Null or missing key for signing encountered processing client \"" + transaction.getOA2Client().getIdentifierString() + "\"");
            throw new IllegalArgumentException("Error: Missing JSON web key. Cannto sign access token.");
        }
        if (getAtData().isEmpty()) return null;
        /*
         Special case: If the claim has a single entry then that is the raw token. Return that. This allows
         handlers in QDL to decide not to return a JWT and just return a standard identifier.
          */
        if (getAtData().size() == 1) {
            String k = String.valueOf(getAtData().keySet().iterator().next());
            String v = String.valueOf(getAtData().get(k));
            oa2se.info("Single value access token for client \"" + transaction.getOA2Client().getIdentifierString() + "\" found. Setting token value to " + v);
            AccessTokenImpl accessToken = new AccessTokenImpl(URI.create(v));
            return accessToken;
        }
        if (!getAtData().containsKey(JWT_ID)) {
            // There is something wrong. This is required.
            throw new IllegalStateException("Error: no JTI. Cannot create access token");
        }
        try {
            String at = JWTUtil2.createJWT(getAtData(), key, headerType);
            URI jti = URI.create(getAtData().getString(JWT_ID));
            AccessTokenImpl at0 = new AccessTokenImpl(at, jti);
            at0.setLifetime(1000 * (getAtData().getLong(EXPIRATION) - getAtData().getLong(ISSUED_AT)));
            return at0;
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

    }


    @Override
    public void setAccountingInformation() {
        JSONObject atData = getAtData();
        // Figure out issuer. If in config, that wins. If not, if the client is
        // in a vo, use the designated at issuer. If that is not set, use the
        // VO issuer. If that fails, get the server issuer from the discovery servlet.
        //
        String issuer = "";

        if (isTrivial(getATConfig().getIssuer())) {
            VirtualOrganization vo = oa2se.getVO(transaction.getClient().getIdentifier());
            if (vo == null) {
                // fail safe. No VO, no configuration, return this service as issuer.
                issuer = OA2DiscoveryServlet.getIssuer(request);
            } else {
                if (!isTrivial(vo.getAtIssuer())) {
                    issuer = vo.getAtIssuer();
                } else {
                    if (isTrivial(vo.getIssuer())) {
                        issuer = vo.getIssuer();
                    } else {
                        issuer = OA2DiscoveryServlet.getIssuer(request);
                    }
                }
            }
        } else {
            // This lets the configuration override the VO.
            issuer = getATConfig().getIssuer();
        }
        atData.put(ISSUER, issuer);
        if (getATConfig().getAudience() != null && !getATConfig().getAudience().isEmpty()) {
            atData.put(AUDIENCE, getATConfig().getAudience());
        }
        // If they really asserted it
        if (getATConfig().hasSubject()) {
            String newSubject = TemplateUtil.replaceAll(getATConfig().getSubject(), atData);
            atData.put(SUBJECT, newSubject);
        }
        if (0 < getATConfig().getLifetime()) {
            atData.put(EXPIRATION, (System.currentTimeMillis() + getATConfig().getLifetime()) / 1000L);
        } else {
            atData.put(EXPIRATION, (System.currentTimeMillis() + OA2ConfigurationLoader.ACCESS_TOKEN_LIFETIME_DEFAULT) / 1000L); // 15 minutes.
        }
        atData.put(NOT_VALID_BEFORE, (System.currentTimeMillis() - 5000L) / 1000L); // not before is 5 minutes before current
        atData.put(ISSUED_AT, System.currentTimeMillis() / 1000L);

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
