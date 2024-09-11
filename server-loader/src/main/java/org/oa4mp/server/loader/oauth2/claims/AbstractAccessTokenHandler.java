package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.server.loader.oauth2.servlet.ClientUtils;
import org.oa4mp.server.loader.oauth2.servlet.OA2DiscoveryServlet;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.vo.VirtualOrganization;
import org.oa4mp.server.loader.oauth2.tokens.AccessTokenConfig;
import org.oa4mp.server.loader.oauth2.tokens.AuthorizationPath;
import org.oa4mp.server.loader.oauth2.tokens.AuthorizationTemplate;
import org.oa4mp.server.loader.oauth2.tokens.AuthorizationTemplates;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import org.oa4mp.delegation.server.OA2Constants;
import org.oa4mp.delegation.server.OA2Scopes;
import org.oa4mp.delegation.server.jwt.AccessTokenHandlerInterface;
import org.oa4mp.delegation.server.jwt.IDTokenHandlerInterface;
import org.oa4mp.delegation.server.jwt.MyOtherJWTUtil2;
import org.oa4mp.delegation.server.server.RFC8693Constants;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.*;

import static org.oa4mp.server.loader.oauth2.claims.ScopeTemplateUtil.doCompareTemplates;
import static org.oa4mp.server.loader.oauth2.claims.ScopeTemplateUtil.replaceTemplate;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.*;

/**
 * Only create an access token handler if you need some special handling, otherwise the
 * default simple token will be used.
 * <p>Created by Jeff Gaynor<br>
 * on 7/21/20 at  2:50 PM
 */
public class AbstractAccessTokenHandler extends AbstractPayloadHandler implements AccessTokenHandlerInterface, IDTokenHandlerInterface {
    public static final String AT_DEFAULT_HANDLER_TYPE = "default";
    public static final String AT_BASIC_HANDLER_TYPE = "access";

    public AbstractAccessTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
    }


    /**
     * The underlying {@link JSONObject} that contains the claims that go in to this access token.
     * Note that the {@link #getUserMetaData()} call will retrieve the user metadata and is not the same as
     * the access token contents!
     *
     * @return
     */
    public JSONObject getPayload() {
        if (payload == null) {
            payload = transaction.getATData();
            if (payload == null) {
                payload = new JSONObject();
            }
        }
        return payload;
    }

    JSONObject userMetaData;

    /**
     * generally for this class you will need to inject the user meta data.
     *
     * @return
     */
    public JSONObject getUserMetaData() {
        return userMetaData;
    }

    public void setUserMetaData(JSONObject userMetaData) {
        this.userMetaData = userMetaData;
    }


    @Override
    public void init() throws Throwable {
        // set some standard claims.
        //if (getPayload().isEmpty()) {
            setAccountingInformation();
        //}
    }

    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        if (req.getArgs().containsKey(SRE_REQ_CLAIMS)) {
            getUserMetaData().putAll((Map) req.getArgs().get(SRE_REQ_CLAIMS));
        }
        if (req.getArgs().containsKey(SRE_REQ_ACCESS_TOKEN)) {
            getPayload().putAll((Map) req.getArgs().get(SRE_REQ_ACCESS_TOKEN));
        }
        req.getArgs().put(SRE_REQ_ACCESS_TOKEN, getPayload());
        req.getArgs().put(SRE_REQ_CLAIMS, getUserMetaData());
    }


    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        super.handleResponse(resp);
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                setUserMetaData((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                setExtendedAttributes((JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES));
                setPayload((JSONObject) resp.getReturnedValues().get(SRE_REQ_ACCESS_TOKEN));
                List<ClaimSource> sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                transaction.setClaimsSources(sources);
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
        Collection<String> requestedAudience = null;
        if (transaction.hasUseTemplates()) {
            requestedAudience = transaction.getUseTemplates();
        } else {
            if (transaction.hasAudience()) {
                requestedAudience = transaction.getAudience();
            }
        }
        // check for audiences.
        if (requestedAudience == null || requestedAudience.isEmpty()) {

            switch (getATConfig().getAudience().size()) {
                case 0:
                    // no audiences configured and none requested.
                    throw new IllegalStateException(" The client has no configured audiences and none were requested. Cannot resolve scopes.");
                case 1:
                    // no audience requested and a single one is configured. Use that.
                    if (requestedAudience == null) {
                        requestedAudience = new ArrayList<>();
                    }
                    requestedAudience.add(getATConfig().getAudience().get(0));
                    break;
                default:
                    // no audiences any place, requested or configured.
                    throw new IllegalStateException(" The client is configured with multiple audiences, but none were requested. Cannot resolve scopes.");
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
        for (Object claimKey : getUserMetaData().keySet()) {
            Object claim = getUserMetaData().get(claimKey);
            // Only groups are allowed to be embedded arrays in claims.
            if (claim instanceof JSONArray) {
                List<String> groupKeys = new ArrayList<>();  // list of groups in the current claims for this user

                JSONArray array = (JSONArray) claim;
                for (int i = 0; i < array.size(); i++) {
                    // Fixes https://github.com/ncsa/oa4mp/issues/125
                    // We may get back an entry of groups. Check it is aa JSON Object,
                    // then check if it has the right structure
                    Object unknownThingie = array.get(i);
                    if (unknownThingie instanceof JSONObject) {
                        JSONObject jo = (JSONObject) unknownThingie;
                        if (jo.containsKey(Groups.GROUP_ENTRY_NAME)) {
                            groupKeys.add(jo.getString(Groups.GROUP_ENTRY_NAME));
                        }
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
                throw new IllegalStateException(" The requested audience \"" + aud + "\" is not valid for this client. Cannot resolve scopes.");
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
        // Non-uris we are going to call capabilities, like in the WLCG spec since it is descriptive
        // E.g. if a scope is like compute.cancel it should not be processed as a template later.
        // Take them out here. Have to avoid concurrent modification exception, so stash them
        Collection<String> requestedCapabilities = new ArrayList<>();
        Collection<String> requestedScopes = null;
        if(isQuery){
            // It is possible that the user sends along scopes in the intial request and still overrides them in the
            // call to the token endpoint.
            requestedScopes = (txRecord != null && txRecord.hasScopes()) ? txRecord.getScopes() : transaction.getScopes();
        } else {
            // Fix for https://github.com/ncsa/oa4mp/issues/165
            requestedScopes = (txRecord != null && txRecord.hasScopes()) ? txRecord.getScopes() : transaction.getATReturnedOriginalScopes();
        }
        Collection<String> badRequests = new ArrayList<>();
        Collection<String> foundCapabilities = new ArrayList<>();
        /*
         * And for the next bit, if a capability is allowed like compute.submit
         * and the user tries to overload it to, e.g. compute.submit:/etc/certs
         * Do not assert the capability.
         *
         */
        for (String x : computedScopes) {
            if (!x.contains(":")) {
                if (requestedScopes.contains(x)) {
                    foundCapabilities.add(x);
                } else {
                    for (String bad : requestedScopes) {
                        if (bad.startsWith(x + ":")) {
                            badRequests.add(bad);
                        }
                    }
                }
                requestedCapabilities.add(x);
            }

        }
        computedScopes.removeAll(requestedCapabilities);
        requestedScopes.remove(badRequests);

        /*
            If there is a token exchange record, then this is being invoked as part of a token
            exchange. In that case, any supplied scopes are used and the templates are used as
            super-paths.
        */

        actualScopes = doCompareTemplates(computedScopes,
                requestedScopes,
                isQuery);


        if(isQuery){
            actualScopes.addAll(foundCapabilities); // add back in relative computed scopes.

        }else{
            if(transaction.hasATReturnedOriginalScopes()){
                for(String fc : foundCapabilities){
                    if(transaction.getATReturnedOriginalScopes().contains(fc)){
                        actualScopes.addAll(foundCapabilities); // add back in relative computed scopes.
                    }
                }
            }
        }

        // now we convert to a scope string.
        String s = OA2Scopes.ScopeUtil.toString(actualScopes);
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
        return transaction.getClaimSources(oa2se);
    }

    public void finish(boolean doTemplates, boolean isQuery) throws Throwable {
        /*
          Make SURE the JTI gets set or token exchange, user info etc. will never work.
         */
        MetaDebugUtil debugger = MyProxyDelegationServlet.createDebugger(client);
        debugger.trace(this, "starting AT handler finish with transaction =" + transaction.summary());
        JSONObject atData = getPayload();
        if (getPhCfg().hasTXRecord()) {
            TXRecord txRecord = getPhCfg().getTxRecord();
            // Fixes CIL-971
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
        refreshAccountingInformation();
        doServerVariables(atData, getUserMetaData());
        setPayload(atData); // If these are updated by the server variable, update.
        if (getPhCfg().hasTXRecord()) {
            getPhCfg().getTxRecord().setToken(getPayload());
        }
        debugger.trace(this, "done  w/ AT handler finish with transaction =" + transaction.summary());

        //   transaction.setAccessTokenLifetime(proposedLifetime);
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


    @Override
    public AccessTokenImpl getSignedPayload(JSONWebKey key) {
        return getSignedPayload(key, MyOtherJWTUtil2.DEFAULT_TYPE);
    }

    @Override
    public AccessTokenImpl getSignedPayload(JSONWebKey key, String headerType) {
        if (key == null) {
            oa2se.warn(" Null or missing key for signing encountered processing client \"" + client.getIdentifierString() + "\"");
            throw new IllegalArgumentException(" Missing JSON web key. Cannot sign access token.");
        }
        if (getPayload().isEmpty()) return null;
           /*
            Special case: If the claim has a single entry then that is the raw token. Return that. This allows
            handlers in QDL to decide not to return a JWT and just return a standard identifier.
             */
        if (getPayload().size() == 1) {
            String k = String.valueOf(getPayload().keySet().iterator().next());
            String v = String.valueOf(getPayload().get(k));
            oa2se.info("Single value access token for client \"" + client.getIdentifierString() + "\" found. Setting token value to " + v);
            AccessTokenImpl accessToken = new AccessTokenImpl(URI.create(v));
            return accessToken;
        }
        if (!getPayload().containsKey(JWT_ID)) {
            // There is something wrong. This is required.
            throw new IllegalStateException(" no JTI. Cannot create access token");
        }
        try {
            String at = MyOtherJWTUtil2.createJWT(getPayload(), key, headerType);
            return TokenFactory.createAT(at);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            // Edge case: It is possible for the JSON utility to blow up if something very odd was sent in a request.
            // Spit the entire thing out so it does not get lost someplace else.
            e.printStackTrace();
            throw new GeneralException("Could not create signed token for payload" + getPayload().toString(1), e);
        }
    }


    @Override
    public void saveState(String execPhase) throws Throwable {
        if (execPhase.equals(SRE_POST_AUTH)) {
            transaction.setATData(getPayload());
            transaction.setAccessTokenLifetime(getPayload().getLong(EXPIRATION) * 1000);
        }
        super.saveState(execPhase);
    }


    @Override
    public void setAccountingInformation() {
        JSONObject atData = getPayload();
        // Figure out issuer. If in config, that wins. If not, if the client is
        // in a vo, use the designated at issuer. If that is not set, use the
        // VO issuer. If that fails, get the server issuer from the discovery servlet.
        //
        String issuer = "";

        if (isTrivial(getATConfig().getIssuer())) {
            VirtualOrganization vo = oa2se.getVO(client.getIdentifier());
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
        // hierarchy.
        // 1. If they passed it in explicitly, use that
        // 2. If it is set in the configuration, use that
        // 3. If there is a VO, use that
        // 4. If all else fails, use the standard issuer
        if (transaction.hasAudience()) {
            atData.put(AUDIENCE, transaction.getAudience());
        } else {
            if (getATConfig().getAudience() != null && !getATConfig().getAudience().isEmpty()) {
                atData.put(AUDIENCE, getATConfig().getAudience());
            } else{
                VirtualOrganization vo = oa2se.getVO(client.getIdentifier());
                if (vo == null) {
                    // fail safe. No VO, no configuration, return this service as issuer.
                    atData.put(AUDIENCE, transaction.getClient().getIdentifierString());
                } else {
                    atData.put(AUDIENCE, vo.getAtIssuer());
                }
            }
        }
        // If they really asserted it
        if (getATConfig().hasSubject()) {
            String newSubject = TemplateUtil.replaceAll(getATConfig().getSubject(), atData);
            atData.put(SUBJECT, newSubject);
        }
        refreshAccountingInformation();

        //     setPayload(atData);
    }

    @Override
    public void refreshAccountingInformation() {
        //   setAccountingInformation();
        JSONObject atData = getPayload();

        long lifetime = ClientUtils.computeATLifetime(transaction, client, oa2se);
        long issuedAt = System.currentTimeMillis();
        long expiresAt = issuedAt + lifetime;

        atData.put(EXPIRATION, expiresAt / 1000L);
        atData.put(NOT_VALID_BEFORE, (issuedAt - 5000L) / 1000L); // not before is 5 minutes before current
        atData.put(ISSUED_AT, issuedAt / 1000L);
        if (hasTXRecord()) {
            getTXRecord().setLifetime(lifetime);
            getTXRecord().setExpiresAt(expiresAt);
            getTXRecord().setIssuedAt(issuedAt);
        }


    }

    public AccessToken getAccessToken() {
        return transaction.getAccessToken();
    }

    public void setAccessToken(AccessToken accessToken) {
        transaction.setAccessToken(accessToken);
    }
}
