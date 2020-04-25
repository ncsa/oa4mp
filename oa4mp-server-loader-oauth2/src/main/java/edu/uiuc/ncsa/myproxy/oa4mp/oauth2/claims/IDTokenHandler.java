package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunRequest;
import edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.DebugUtil.trace;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.AUTHORIZATION_TIME;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.NONCE;
import static edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/20 at  6:51 AM
 */
public class IDTokenHandler extends AbstractPayloadHandler {
    protected String issuer;

    public IDTokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction, HttpServletRequest request) {
        super(oa2se,transaction,request);
        setIssuer(request);
    }

    public IDTokenHandler(OA2SE oa2se, OA2ServiceTransaction transaction) {
        super(oa2se,transaction);
    }


    protected void setIssuer(HttpServletRequest request) {
        issuer = null;
        // So in order
        // 1. get the issuer from the admin client
        List<Identifier> admins = oa2se.getPermissionStore().getAdmins(transaction.getClient().getIdentifier());

        for (Identifier adminID : admins) {
            AdminClient ac = oa2se.getAdminClientStore().get(adminID);
            if (ac != null) {
                if (ac.getIssuer() != null) {
                    issuer = ac.getIssuer();
                    break;
                }
            }
        }
        // 2. If the admin client does not have an issuer set, see if the client has one
        if (issuer == null) {
            issuer = ((OA2Client) transaction.getClient()).getIssuer();
        }

        // 3. If the client does not have one, see if there is a server default to use
        // The discovery servlet will try to use the server default or construct the issuer
        if (issuer == null) {
            issuer = OA2DiscoveryServlet.getIssuer(request);
        }

    }
      void addDebugClaims(){
           claims.put("eppn","jgaynor@illinois.edu");
           claims.put("idp","https://idp.ncsa.illinois.edu/idp/shibboleth");
      }
    @Override
    public void init() throws Throwable {
        claims = getClaims();
        trace(this, "Starting to process basic claims");
  //      addDebugClaims();
        claims.put(OA2Claims.ISSUER, issuer);
        claims.put(OA2Claims.SUBJECT, transaction.getUsername());
        claims.put(AUDIENCE, transaction.getClient().getIdentifierString());
        claims.put(OA2Constants.ID_TOKEN_IDENTIFIER, ((OA2TokenForge) oa2se.getTokenForge()).getIDToken().getToken());
        // now set all the timestamps and such.
        setAccountingInformation();
        checkRequiredScopes(transaction);
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims.
            return;
        }

        trace(this, "Starting to process server default claims");

        if (oa2se != null && oa2se.getClaimSource() != null && oa2se.getClaimSource().isEnabled() && oa2se.getClaimSource().isRunAtAuthorization()) {
            DebugUtil.trace(this, "Service environment has a claims source enabled=" + oa2se.getClaimSource());

            // allow the server to pre-populate the claims. This invokes the global claims handler for the server
            // to allow, e.g. pulling user information out of HTTP headers or perhaps a user database.
            oa2se.getClaimSource().process(claims, request, transaction);
        } else {
            trace(this, "Service environment has a claims no source enabled during authorization");
        }
    }

    @Override
    public void setAccountingInformation() {
        claims = getClaims();

        trace(this, "Starting to set the accounting information for the claims");
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        claims.put(EXPIRATION, System.currentTimeMillis() / 1000 + 15 * 60); // expiration is in SECONDS from the epoch.
        claims.put(ISSUED_AT, System.currentTimeMillis() / 1000); // issued at = current time in seconds.
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        if (transaction.getNonce() != null && 0 < transaction.getNonce().length()) {
            claims.put(NONCE, transaction.getNonce());
        }
    }



    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_CLAIMS, getClaims());
        req.getArgs().put(SRE_REQ_CLAIM_SOURCES, getSources()); // so its a map
        req.getArgs().put(SRE_REQ_EXTENDED_ATTRIBUTES, getExtendedAttributes()); // so its a map
    }

    @Override
    public void handleResponse(ScriptRunResponse resp) throws Throwable {
        switch (resp.getReturnCode()) {
            case ScriptRunResponse.RC_OK:
                // Note that the returned values from a script are very unlikely to be the same object we sent
                // even if the contents are the same, since scripts may have to change these in to other data structures
                // to make them accessible to their machinery, then convert them back.
                claims = (JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS);
                sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                extendedAttributes = (JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES);
            case ScriptRunResponse.RC_NOT_RUN:
                return;

        }
    }

    @Override
    public void checkClaims() throws Throwable {
        if (oa2se.isOIDCEnabled()) {
            checkClaim(getClaims(), SUBJECT);
        }
        // Remove empty claims. One should not assert empty claims.
        // Get the keys to remove then remove them or you get a concurrent modification exception.
        ArrayList<String> keysToRemove = new ArrayList<>();
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

    List<ClaimSource> sources = null;

    @Override
    public List<ClaimSource> getSources() throws Throwable {
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims. 
            return new ArrayList<>();
        }
        if (sources == null) {
            sources = transaction.getClaimSources(oa2se);
        }
        return sources;
    }


    /**
     * For CIL-499. It is possible to remove key claims with functors and return unusable claims objects. This method
     * will check that claims that <b>must</b> be present are there or will raise a server-side exception.
     */
    @Override
    public void finish() throws Throwable {
        // only required one by the spec. and only if the server is OIDC.
        if (oa2se.isOIDCEnabled()) {
            checkClaim(getClaims(), SUBJECT);
        }
    }

    @Override
    public void saveState() throws Throwable {
        if (transaction != null && oa2se != null) {
            transaction.setClaims(getClaims());
            transaction.setClaimsSources(getSources());
            oa2se.getTransactionStore().save(transaction);
        } else {
            trace(this, "In saveState: either env or transaction null. Nothing saved.");
        }
    }



    /**
     * Use this to check for any requires scopes that the request must have. It is usually best to check these in the
     * transaction since they have been normalized there, but the request is supplied too for completeness.
     *
     * @param t
     * @throws Throwable
     */
    protected void checkRequiredScopes(OA2ServiceTransaction t) throws Throwable {
        if (oa2se.isOIDCEnabled() && !t.getScopes().contains(OA2Scopes.SCOPE_OPENID)) {
            throw new OA2GeneralError(OA2Errors.INVALID_SCOPE, "invalid scope: no open id scope", HttpStatus.SC_UNAUTHORIZED);
        }
    }

    protected void checkClaim(JSONObject claims, String claimKey) {
        if (claims.containsKey(claimKey)) {
            if (isEmpty(claims.getString(claimKey))) {
                //           DebugUtil.trace(this, "Missing \"" + claimKey+ "\" claim= " );
                throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Missing " + claimKey + " claim", HttpStatus.SC_INTERNAL_SERVER_ERROR);
            }
        } else {
            throw new OA2GeneralError(OA2Errors.SERVER_ERROR, "Missing " + claimKey + " claim", HttpStatus.SC_INTERNAL_SERVER_ERROR);
        }
    }


}
