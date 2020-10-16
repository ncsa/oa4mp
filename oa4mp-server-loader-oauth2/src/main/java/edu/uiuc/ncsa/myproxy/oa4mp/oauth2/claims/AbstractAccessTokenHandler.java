package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AccessTokenConfig;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationPath;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationTemplate;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.AuthorizationTemplates;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.AccessTokenHandlerInterface;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.JWTUtil2;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * Only create an access token handler if you need some special handling, otherwise the
 * default simple token will be used.
 * <p>Created by Jeff Gaynor<br>
 * on 7/21/20 at  2:50 PM
 */
public class AbstractAccessTokenHandler extends AbstractPayloadHandler implements AccessTokenHandlerInterface {
    public static final String AT_DEFAULT_HANDLER_TYPE = "default";

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
        if (atData == null) {
            atData = transaction.getATData();
        }
        return atData;
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
        switch (resp.getReturnCode()) {
            case ScriptRunResponse.RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                claims = (JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS);
                //sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                extendedAttributes = (JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES);
                atData = (JSONObject) resp.getReturnedValues().get(SRE_REQ_ACCESS_TOKEN);
            case ScriptRunResponse.RC_NOT_RUN:
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
    public String resolveTemplates() {
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
        Collection<String> requestedScopes = transaction.getScopes();
        Collection<String> requestedAudience = transaction.getAudience();

        // check for audiences.
        if (requestedAudience == null || requestedAudience.isEmpty()) {

            switch (getATConfig().getAudience().size()) {
                case 0:
                    // no audiences configured and none requested.
                    throw new IllegalStateException("Error: The client has no configured audiences and none were requested. Cannot resolve scopes.");
                case 1:
                    // no audience requested and a single one is configured. Use that.
                    if(requestedAudience == null){
                        requestedAudience = new ArrayList<>();
                    }
                    requestedAudience.add(getATConfig().getAudience().get(0));
                    break;
                default:
                    // no audiences any place, requested or configured.
                    throw new IllegalStateException("Error: The client is configured with multiple audiences, but none were requested. Cannot resolve scopes.");
            }
        }
        Set<String> computedScopes = new HashSet<>(); // makes sure there are unique scopes.
        List<String> groupKeys = new ArrayList<>();
        for (Object claim : getClaims().keySet()) {
            Object x = getClaims().get(claim);
            if (x instanceof Groups) {
                groupKeys.add(claim.toString());
            }
        }
        // So we have groups (if any) and we have target audiences (at least one, perhaps a default).
        // Next up is we have to look at all templates stored by audience and do the appropriate replacement
        // If the replaced version is one of the requested scopes, add it to the computedScopes to get returned.
        // If not, ignore it.
        for (String aud : requestedAudience) {
            if (!templates.containsKey(aud)) {
                throw new IllegalStateException("Error: The requested audience \"" + aud + "\" is not valid for this client. Cannot resolve scopes.");
            }
            AuthorizationTemplate template = templates.get(aud);
            for (AuthorizationPath authorizationPath : template.getPaths()) {
                String z = replaceTemplate(authorizationPath.toString(), groupKeys);
                if (z != null) {
                    computedScopes.add(z);
                }
            }
        }
        // now we convert to a scope string.
        String s = "";
        boolean firstPass = true;
        for (String x : computedScopes) {
            if (firstPass) {
                firstPass = false;
                s = x;
            } else {
                s = s + " " + x;
            }
        }
        if(StringUtils.isTrivial(s)){
            return null;
        }
        return s;

    }

    /**
     * resolve a single template for groups (if any) and other claims.  Returns the scope if this checks out
     * or null if there is no such match.
     *
     * @param currentTemplate
     * @param groups
     */
    protected String replaceTemplate(String currentTemplate, List<String> groups) {
        if (groups.isEmpty()) {
            return simpleReplacement(currentTemplate);
        }
        for (String g : groups) {
            String claimKey = TemplateUtil.REGEX_LEFT_DELIMITER + g + TemplateUtil.REGEX_RIGHT_DELIMITER;
            if (currentTemplate.contains(claimKey)) {

                Groups groups1 = (Groups) getClaims().get(g);
                for (String p : groups1.keySet()) {
                    String newPath = currentTemplate.replace(claimKey, p); // replace the ${group_claim} with its value
                    String replacedTemplate = simpleReplacement(newPath);
                    if (replacedTemplate != null) {
                        return replacedTemplate;
                    }
                }
            }
        }
        return null;
    }

    protected String simpleReplacement(String currentTemplate) {
        String newPath = TemplateUtil.replaceAll(currentTemplate, getClaims());
        if (transaction.getScopes().contains(newPath)) {
            return newPath;
        }
        return null;
    }

    /**
     * Convenience to peel off the {@link AccessTokenConfig} from the handler config and return it.
     *
     * @return
     */
    protected AccessTokenConfig getATConfig() {
        return (AccessTokenConfig) getPhCfg().clientConfig;
    }

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        return new ArrayList<>();
    }

    public void finish(boolean doTemplates) throws Throwable {
        /*
          Make SURE the JTI gets set or token exchange, user info etc. will never work.
         */
        JSONObject atData = getAtData();
        if (transaction.getAccessToken() != null) {
            atData.put(JWT_ID, transaction.getAccessToken().getToken());
        }
        if(doTemplates) {
            String scopes = resolveTemplates();
            if (scopes != null) {
                atData.put(OA2Constants.SCOPE, scopes);
            }
        }
        setAtData(atData);

    }
    @Override
    public void finish() throws Throwable {
        finish(true);
    }

    /**
     * Gets the AT data object (which has all the claims in it) and returns a signed access token.
     * This does <b>not</b> set the access token in the transaction but leaves up to the calling
     * application what to do, since different tokens have different contracts.
     *
     * @return
     */
    @Override
    public AccessToken getSignedAT(JSONWebKey key) {
        if (key == null) {
            oa2se.warn("Error: Null or missing key for signing encountered processing client \"" + transaction.getOA2Client().getIdentifierString() + "\"");
            throw new IllegalArgumentException("Error: A null JSON web key was encountered");
        }
        if (getAtData().isEmpty()) return null;
        /*
         Special case: If the claim has a single entry then that is the raw token. Return that. This allows
         handlers in QDL to decide not to return a JWT and just return a standard identifier.
          */
         if(getAtData().size() == 1){
             String k = String.valueOf(getAtData().keySet().iterator().next());
             String v = String.valueOf(getAtData().get(k));
             oa2se.info("Single value access token for client \"" + transaction.getOA2Client().getIdentifierString() + "\" found. Setting token value to " + v);
             AccessTokenImpl accessToken = new AccessTokenImpl(URI.create(v));
             return accessToken;
         }
        try {
            String at = JWTUtil2.createJWT(getAtData(), key);
            URI x = URI.create(at);
            return new AccessTokenImpl(x);
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
        if (transaction != null && oa2se != null) {
            transaction.setATData(getAtData());

            oa2se.getTransactionStore().save(transaction);
        } else {
            trace(this, "In saveState: either env or transaction null. Nothing saved.");
        }
    }

    @Override
    public void setAccountingInformation() {
        JSONObject atData = getAtData();
        atData.put(ISSUER, getATConfig().getIssuer());
        if (0 < getATConfig().getLifetime()) {
            atData.put(EXPIRATION, (System.currentTimeMillis() + getATConfig().getLifetime()) / 1000L);
        } else {
            atData.put(EXPIRATION, (System.currentTimeMillis() / 1000L) + 900L); // 15 minutes.
        }
        atData.put(NOT_VALID_BEFORE, (System.currentTimeMillis() - 5000L) / 1000L); // not before is 5 minutes before current
        //atData.put(ISSUER, oa2se.getIssuer());
        //atData.put(EXPIRATION, System.currentTimeMillis() / 1000L + 900L);
        atData.put(ISSUED_AT, System.currentTimeMillis() / 1000L);
/*        if (transaction.getAccessToken() != null) {
            atData.put(JWT_ID, transaction.getAccessToken().getToken());
        }*/
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
