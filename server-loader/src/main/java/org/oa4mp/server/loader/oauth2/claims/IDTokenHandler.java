package org.oa4mp.server.loader.oauth2.claims;

import org.oa4mp.server.loader.oauth2.servlet.ClientUtils;
import org.oa4mp.server.loader.oauth2.servlet.OA2DiscoveryServlet;
import org.oa4mp.server.loader.oauth2.servlet.OA2HeaderUtils;
import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.vo.VirtualOrganization;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.delegation.common.token.impl.IDTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import org.oa4mp.delegation.server.jwt.IDTokenHandlerInterface;
import org.oa4mp.delegation.server.server.claims.ClaimSource;
import org.oa4mp.delegation.server.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;
import org.oa4mp.delegation.server.*;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

import static org.oa4mp.delegation.server.OA2Constants.AUTHORIZATION_TIME;
import static org.oa4mp.delegation.server.OA2Constants.NONCE;
import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_NOT_RUN;
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.RC_OK;
import static edu.uiuc.ncsa.security.util.scripting.ScriptingConstants.*;
import static org.oa4mp.delegation.server.server.claims.OA2Claims.*;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/20 at  6:51 AM
 */
public class IDTokenHandler extends AbstractPayloadHandler implements IDTokenHandlerInterface {
    protected String issuer;
    public static final String ID_TOKEN_DEFAULT_HANDLER_TYPE = "default";
    public static final String ID_TOKEN_BASIC_HANDLER_TYPE = "identity";

    public IDTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
        if (payloadHandlerConfig.getRequest() != null) {
            setIssuer(payloadHandlerConfig.getRequest());
        }
    }

    @Override
    public JSONObject getPayload() {
        if (payload == null) {
            payload = transaction.getUserMetaData();
            if (payload == null) {
                payload = new JSONObject();
            }
        }
        return payload;

    }

    public JSONObject getUserMetaData() {
        return getPayload();
    }

    public void setUserMetaData(JSONObject userMetaData) {
        setPayload(userMetaData);
    }


    protected void setIssuer(HttpServletRequest request) {
        issuer = null;
        // So in order
        VirtualOrganization vo = oa2se.getVO(transaction.getClient().getIdentifier());
        DebugUtil.trace(this, "vo = " + vo);
        if (vo != null) {
            issuer = vo.getIssuer();
            // if issuer set, return it.
            if (!isTrivial(issuer)) {
                return;
            }
        }
        // 1. get the issuer from the admin client
        List<Identifier> admins = oa2se.getPermissionStore().getAdmins(transaction.getClient().getIdentifier());

        for (Identifier adminID : admins) {
            AdminClient ac = oa2se.getAdminClientStore().get(adminID);
            if (ac != null) {
                if (!isTrivial(ac.getIssuer())) {
                    issuer = ac.getIssuer();
                    DebugUtil.trace(this, "got issuer from admin client \"" + ac.getIdentifierString() + "\" =" + issuer);
                    break;
                }
            }
        }
        // 2. If the admin client does not have an issuer set, see if the client has one
        if (isTrivial(issuer)) {
            issuer = ((OA2Client) transaction.getClient()).getIssuer();
            DebugUtil.trace(this, "got issuer from  client \"" + transaction.getClient().getIdentifierString() + "\" =" + issuer);

        }

        // 3. If the client does not have one, see if there is a server default to use
        // The discovery servlet will try to use the server default or construct the issuer
        if (isTrivial(issuer)) {
            issuer = OA2DiscoveryServlet.getIssuer(request);
            DebugUtil.trace(this, "got issuer from  discovery servlet  =" + issuer);
        }
        DebugUtil.trace(this, "RETURNED issuer  =" + issuer);

    }

    boolean IDP_DEBUG_ON = false;


    @Override
    public void init() throws Throwable {
        JSONObject claims = getUserMetaData();
        trace(this, "Starting to process basic claims");
        // It is possible that the claims are already somewhat populated. Only initialize
        // claims that have not been set.
        setClaimIfNeeded(claims, ISSUER, issuer);
        setClaimIfNeeded(claims, OA2Claims.SUBJECT, transaction.getUsername());

        setClaimIfNeeded(claims, AUDIENCE, transaction.getClient().getIdentifierString());
        setClaimIfNeeded(claims, OA2Constants.ID_TOKEN_IDENTIFIER, ((OA2TokenForge) oa2se.getTokenForge()).getIDToken().getToken());
        // now set all the timestamps and such.
        setAccountingInformation();
        checkRequiredScopes(transaction);
        if (client.isPublicClient()) {
            // Public clients do not get more than basic claims.
            //   transaction.setUserMetaData(claims); // make sure this is available to the next handler
            return;
        }

        trace(this, "Starting to process server default claims");

        if (oa2se != null && oa2se.getClaimSource() != null && oa2se.getClaimSource().isEnabled() && oa2se.getClaimSource().isRunOnlyAtAuthorization()) {
            DebugUtil.trace(this, "Service environment has a claims source enabled=" + oa2se.getClaimSource());

            // allow the server to pre-populate the claims. This invokes the global claims handler for the server
            // to allow, e.g. pulling user information out of HTTP headers or perhaps a user database.
            oa2se.getClaimSource().process(claims, request, transaction);
        } else {
            trace(this, "Service environment has a claims no source enabled during authorization");
        }
    }

    private void setClaimIfNeeded(JSONObject claims, String claimName, Object claimValue) {
        if (!claims.containsKey(claimName)) {
            claims.put(claimName, claimValue);
        }
    }

    @Override
    public void refreshAccountingInformation() {
        NEWrefreshAccountingInformation();
    }

    protected void NEWrefreshAccountingInformation() {
        trace(this, "Refreshing the accounting information for the claims");
        getUserMetaData().put(ISSUED_AT, System.currentTimeMillis() / 1000);
        getUserMetaData().put(NOT_VALID_BEFORE, System.currentTimeMillis() / 1000);
        long idtLifetime = ClientUtils.computeIDTLifetime(transaction, client, oa2se);
        long expiresAt = System.currentTimeMillis() + idtLifetime;
        getUserMetaData().put(EXPIRATION, expiresAt / 1000); // expiration is in SECONDS from the epoch.
/*        if(hasTXRecord()){
            getTXRecord().setLifetime(idtLifetime);
            getTXRecord().setExpiresAt(expiresAt);
        }*/
        trace(this, "saving the transaction with claims:\n" + getUserMetaData().toString(1));
    }


    @Override
    public void setAccountingInformation() {
        trace(this, "Setting the accounting information for the claims");
        if (transaction.getNonce() != null && 0 < transaction.getNonce().length()) {
            getUserMetaData().put(NONCE, transaction.getNonce());
        }
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            // Fix CIL-906
            getUserMetaData().put(AUTHORIZATION_TIME, transaction.getAuthTime().getTime() / 1000); // spec says this is an integer
        }
        refreshAccountingInformation();
    }


    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        // If there are server scripts, there may be claims already set.
        // check and just integrate them
        if (req.getArgs().containsKey(SRE_REQ_CLAIMS)) {
            getUserMetaData().putAll((Map) req.getArgs().get(SRE_REQ_CLAIMS));
        }
        if (req.getArgs().containsKey(SRE_REQ_CLAIM_SOURCES)) {
            List<ClaimSource> sources = (List<ClaimSource>) req.getArgs().get(SRE_REQ_CLAIM_SOURCES);
            sources.addAll(transaction.getClaimSources(oa2se));
            transaction.setClaimsSources(sources);
        }
        // Now grab the complete information this handler knows about.
        req.getArgs().put(SRE_REQ_CLAIM_SOURCES, getSources());
        req.getArgs().put(SRE_REQ_CLAIMS, getUserMetaData());
        if (getPhCfg().request != null) {
            JSONObject json = OA2HeaderUtils.headerToJSON(getPhCfg().request,
                    Arrays.asList(new String[]{"authorization", "cookie", "host"}));
            if (!json.isEmpty()) {
                req.getArgs().put(SRE_REQ_AUTH_HEADERS, json);
            }
        }
/*
        req.getArgs().put(SRE_REQ_EXTENDED_ATTRIBUTES, getExtendedAttributes()); // so its a map*/
    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        super.handleResponse(resp);
        switch (resp.getReturnCode()) {
            case RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                // Update the transaction here because if you do not, then values don't chain between
                // handlers. The transaction is the medium of communication.
                setUserMetaData((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                List<ClaimSource> sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                transaction.setClaimsSources(sources);
                return;
            case RC_NOT_RUN:
                return;

        }
    }

    @Override
    public void checkClaims() throws Throwable {
        if (oa2se.isOIDCEnabled() && client.isPublicClient()) {
            checkClaim(getUserMetaData(), SUBJECT);
        }
        // Remove empty claims. One should not assert empty claims.
        // Get the keys to remove then remove them or you get a concurrent modification exception.
        ArrayList<String> keysToRemove = new ArrayList<>();
        JSONObject claims = getUserMetaData();

        for (Object key : claims.keySet()) {
            if (key == null) {
                keysToRemove.add(null);
            }
            String k = key.toString();
            if (k.isEmpty()) {
                keysToRemove.add("");
            }
            if (claims.get(key) == null || claims.getString(k).isEmpty()) {
                keysToRemove.add(k);
            }
        }
        for (String key : keysToRemove) {
            DebugUtil.trace(this, "Removed empty claim \"" + key + "\"");
            claims.remove(key);
        }
    }


    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return transaction.getClaimSources(oa2se);
    }


    /**
     * For CIL-499. It is possible to remove key claims with functors and return unusable claims objects. This method
     * will check that claims that <b>must</b> be present are there or will raise a server-side exception.
     */
    @Override
    public void finish(String execPhase) throws Throwable {
        refreshAccountingInformation();
        List<String> basicScopes = Arrays.asList(OA2Scopes.basicScopes);
        HashSet<String> x = new HashSet<>();
        x.addAll(getScopes());
        x.retainAll(basicScopes);
        x.retainAll(transaction.getClient().getScopes());
        // All we want is the scopes allowed to this client
        if (x.contains(OA2Scopes.SCOPE_CILOGON_INFO) || !((OA2Client) transaction.getClient()).useStrictScopes()) {
            permissiveFinish(x, execPhase);
            return;
        }
        restrictiveFinish(x, execPhase);
    }

    Collection<String> scopes = null;

    /**
     * Contract is to return the current scopes. If these are not overridden, return
     * the original scopes, which as still in effect.
     *
     * @return
     */
    public Collection<String> getScopes() {
        if (scopes == null) {
            if (hasTXRecord() && getTXRecord().getScopes() != null && !getTXRecord().getScopes().isEmpty()) {
                scopes = getTXRecord().getScopes();
                Collection<String> metadataScopes = OA2Scopes.ScopeUtil.intersection(OA2Scopes.ScopeUtil.getBasicScopes(), scopes);
                if (metadataScopes.size() == 0) {
                    // So the user sent a bunch of scopes and these are not related to user meta data.
                    // Treat this as if they had sent NO scopes, and return the original set.
                    // If there is even one meta data scope, assume they are trying to downscope and let them.
                    metadataScopes = OA2Scopes.ScopeUtil.intersection(OA2Scopes.ScopeUtil.getBasicScopes(), transaction.getScopes());
                    scopes.addAll(metadataScopes);
                }
            } else {
                scopes = transaction.getScopes();
            }
        }
        return scopes;
    }

    /**
     * Restrictive finish = user must explicitly request things and will be limited to them.
     * The model here is that the claim source gets whatever, but the results are filtered
     * to a restricted subset.
     *
     * @param execPhase
     * @throws Throwable
     */
    protected void restrictiveFinish(Collection<String> scopes, String execPhase) throws Throwable {
        JSONObject finalClaims = new JSONObject();
        JSONObject currentClaims = new JSONObject();
        //Collection<String> scopes = getScopes();
        currentClaims.putAll(getUserMetaData());
        // These are to present in every ID token.
        String[] requiredClaims = new String[]{ISSUER, AUDIENCE, EXPIRATION, ISSUED_AT, JWT_ID, NONCE, AUTHORIZATION_TIME};
        for (String r : requiredClaims) {
            setCurrentClaim(currentClaims, finalClaims, r);
        }
        // The strategy is that only what is allowed may be returned.
        // Fix for https://github.com/ncsa/oa4mp/issues/158 follows.
        // As per OIDC spec, if present MUST contain the identifier for the client
        finalClaims.put(AUTHORIZED_PARTY, transaction.getClient().getIdentifierString());
        if (scopes.contains(OA2Scopes.SCOPE_OPENID)) {
            setCurrentClaim(currentClaims, finalClaims, SUBJECT);
            setCurrentClaim(currentClaims, finalClaims, AUTHENTICATION_CLASS_REFERENCE);
            setCurrentClaim(currentClaims, finalClaims, AUTHENTICATION_METHOD_REFERENCE);
        }
        // CIL-1411 -- remove any claims not specifically requested by the user.
        // We need this here since a policy set  may add claims that the user
        // did not request.
        if (scopes.contains(SCOPE_EMAIL)) {
            setCurrentClaim(currentClaims, finalClaims, EMAIL);
            setCurrentClaim(currentClaims, finalClaims, EMAIL_VERIFIED); // we usually don't do this though.
        }
        if (scopes.contains(SCOPE_PHONE)) {
            setCurrentClaim(currentClaims, finalClaims, PHONE_NUMBER);
            setCurrentClaim(currentClaims, finalClaims, PHONE_NUMBER_VERIFIED);
        }

        if (scopes.contains(OA2Scopes.SCOPE_PROFILE)) {
            setCurrentClaim(currentClaims, finalClaims, NAME);
            setCurrentClaim(currentClaims, finalClaims, GIVEN_NAME);
            setCurrentClaim(currentClaims, finalClaims, FAMILY_NAME);
            setCurrentClaim(currentClaims, finalClaims, MIDDLE_NAME);
            setCurrentClaim(currentClaims, finalClaims, NICKNAME);
            setCurrentClaim(currentClaims, finalClaims, DISPLAY_NAME);
            setCurrentClaim(currentClaims, finalClaims, PREFERRED_USERNAME);
        }
        if (scopes.contains(OA2Scopes.SCOPE_ADDRESS)) {
            setCurrentClaim(currentClaims, finalClaims, ADDRESS);
        }

        // these are things that may be returned as user information
        // Fix for https://github.com/ncsa/oa4mp/issues/112
        if (scopes.contains(OA2Scopes.SCOPE_USER_INFO)) {
            for (String claim : USER_INFO_CLAIMS) {
                setCurrentClaim(currentClaims, finalClaims, claim);
            }
        }
        setUserMetaData(finalClaims);
    }

    /**
     * Permissive finish = whittle down certain claims that are not explicit, and
     * pass back everything else. This is needed for scripting where claims may
     * be simply added. If a client is set to strict scopes, adding claims in a script
     * will have them stripped off.
     * CILogon uses this by default since the scopes they get come from SAML assertions
     *
     * @param execPhase
     * @throws Throwable
     */
    protected void permissiveFinish(Collection<String> scopes, String execPhase) throws Throwable {
        // only required one by the spec. and only if the server is OIDC.
        if (oa2se.isOIDCEnabled()) {
            checkClaim(getUserMetaData(), SUBJECT);
        }
        // The strategy is that th is subtractive: the current metadata may have certain things
        // removed, but everything else is returned.
        //Collection<String> scopes = getScopes();
        // CIL-1411 -- remove any claims not specifically requested by the user.
        // We need this here since a policy set  may add claims that the user
        // did not request.
        if (!scopes.contains(OA2Scopes.SCOPE_EMAIL)) {
            getUserMetaData().remove(EMAIL);
            getUserMetaData().remove(EMAIL_VERIFIED);
        }
        if (!scopes.contains(SCOPE_PHONE)) {
            getUserMetaData().remove(PHONE_NUMBER);
            getUserMetaData().remove(PHONE_NUMBER_VERIFIED);
        }
        if (!scopes.contains(OA2Scopes.SCOPE_PROFILE)) {
            getUserMetaData().remove(NAME);
            getUserMetaData().remove(MIDDLE_NAME);
            getUserMetaData().remove(NICKNAME);
            getUserMetaData().remove(GIVEN_NAME);
            getUserMetaData().remove(FAMILY_NAME);
            getUserMetaData().remove(PREFERRED_USERNAME);
            getUserMetaData().remove(DISPLAY_NAME);
        }
        // Not having the CILogon userinfo scope but also allowing other scopes means
        // removing specific scopes and letting other scopes -- such COManage memberships -- through.
        // Fix for https://github.com/ncsa/oa4mp/issues/158
        if (scopes.contains(OA2Scopes.SCOPE_CILOGON_INFO)) {
            return; // contract for this is kitchen sink -- return everything not prohibited.
        }
        if (!scopes.contains(OA2Scopes.SCOPE_USER_INFO)) {
            for (String claim : USER_INFO_CLAIMS) {
                getUserMetaData().remove(claim);
            }
        }
        // everything else gets passed back.
    }

    protected void setCurrentClaim(JSONObject currentClaims, JSONObject finalClaims, String key) {
        if (currentClaims.containsKey(key) && currentClaims.get(key) != null) {
            finalClaims.put(key, currentClaims.get(key));
        }
    }

    @Override
    public void saveState(String execPhase) throws Throwable {
        if (execPhase.equals(SRE_POST_AUTH)) {
            transaction.setUserMetaData(getUserMetaData());
        }
        super.saveState(execPhase);
    }


    /**
     * Use this to check for any requires scopes that the request must have. It is usually best to check these in the
     * transaction since they have been normalized there, but the request is supplied too for completeness.
     *
     * @param t
     * @throws Throwable
     */
    protected void checkRequiredScopes(OA2ServiceTransaction t) throws Throwable {
        if (oa2se.isOIDCEnabled()) {
            if (t.getOA2Client().isPublicClient() && !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "invalid scope: no open id scope",
                        HttpStatus.SC_UNAUTHORIZED,
                        t.getRequestState(),
                        t.getCallback(), t.getClient());

            }
            if (t.getOA2Client().getScopes().contains(OA2Scopes.SCOPE_OPENID) && !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
                throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                        "invalid scope: no open id scope",
                        HttpStatus.SC_UNAUTHORIZED,
                        t.getRequestState(),
                        t.getCallback(), t.getClient());

            }

        }
    }

    /**
     * Enforces that the claim exists in the claims argument. This is mostly
     * used for the openid scope. An error is raised if ths claim is missing.
     *
     * @param claims
     * @param claimKey
     */
    protected void checkClaim(JSONObject claims, String claimKey) {
        if (claims.containsKey(claimKey)) {
            if (isEmpty(claims.getString(claimKey))) {
                //           DebugUtil.trace(this, "Missing \"" + claimKey+ "\" claim= " );
                throw new OA2GeneralError(OA2Errors.SERVER_ERROR,
                        "Missing " + claimKey + " claim",
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        null);
            }
        } else {
            throw new OA2GeneralError(OA2Errors.SERVER_ERROR,
                    "Missing " + claimKey + " claim",
                    HttpStatus.SC_INTERNAL_SERVER_ERROR,
                    null);
        }
    }

    @Override
    public JSONObject execute(ClaimSource source, JSONObject claims) throws Throwable {
        if (client.isPublicClient()) {
            // Public clients do not get more than basic claims.
            return claims;
        }
        return super.execute(source, claims);
    }

    @Override
    public IDTokenImpl getSignedPayload(JSONWebKey key) {
        return getSignedPayload(key, null);
    }

    @Override
    public IDTokenImpl getSignedPayload(JSONWebKey key, String headerType) {
        String idTokken = null;
        try {
            if (client.isSignTokens()) {
                idTokken = JWTUtil.createJWT(getPayload(), key);
            } else {
                idTokken = JWTUtil.createJWT(getPayload());
            }
            return TokenFactory.createIDT(idTokken);
        } catch (Throwable e) {
            throw new IllegalStateException("cannot create ID token", e);
        }

    }
}
