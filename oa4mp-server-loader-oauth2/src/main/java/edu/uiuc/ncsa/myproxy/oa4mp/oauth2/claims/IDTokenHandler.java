package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.IDTokenHandlerInterface;
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
import static edu.uiuc.ncsa.security.util.scripting.ScriptRunResponse.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/16/20 at  6:51 AM
 */
public class IDTokenHandler extends AbstractPayloadHandler implements IDTokenHandlerInterface {
    protected String issuer;

    public IDTokenHandler(PayloadHandlerConfigImpl payloadHandlerConfig) {
        super(payloadHandlerConfig);
        if (payloadHandlerConfig.getRequest() != null) {
            setIssuer(payloadHandlerConfig.getRequest());
        }
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

    boolean IDP_DEBUG_ON = false;

    /**
     * *****************
     * KEEP THIS!   *
     * *****************
     * This lets you turn on or off claims that can emulate coming in from other IDPs with
     * any information you want. Simply add a call to it in the {@link #init()} method.
     * Be sure to turn it off before release since it will put a large ugly warning message in
     * the claims. Look in OA2FunctorTests for more examples.
     */
    void addDebugClaims() {
        // Keep the next two line no matter what, that way you don't leave it in test mode
        // since the claims will tell you.
//        getClaims().put("DEBUG", "If you see this, the server is in test mode. Tell the admin ASAP!");

        DebugUtil.info(this, "addDebugClaims: Testing claims added. ");

        // Uncomment the pair of these you need.

        // NCSA IDP
        //getClaims().put("idp", "https://idp.ncsa.illinois.edu/idp/shibboleth");
        //getClaims().put("eppn", "jgaynor@illinois.edu");
        //getClaims().put("eptid", "jgaynor@rndom3453.eptid");

        // ORCID IDP
        // getClaims().put("idp", "http://orcid.org/oauth/authorize");
        // getClaims().put("oidc", "httpAnoth://orcid.org/5437-7582-1853-4673");

        //FNAL (FermiLab) testing.
        /* *******************
             Note that his has to match the kludge in the OA2ClientUtils or it won't work right.
         *********************/
        boolean jeffTest =
                transaction.getUsername().equals("http://cilogon.org/serverD/users/55") // me via NCSA IDP on polod
                        ||
                        transaction.getUsername().equals("http://cilogon.org/serverA/users/16316"); // me via Google IDP, cilogon.org email on poloc

        boolean jimTest =
                transaction.getUsername().equals("http://cilogon.org/serverD/users/65") // jim Basney NCSA IDP on polod
                        ||
                        transaction.getUsername().equals("http://cilogon.org/serverT/users/37233"); // jim Basney NCSA IDP on poloc


        DebugUtil.trace(this, "In add debug claims. Username = " + transaction.getUsername() +
                ", myproxy username = " + transaction.getMyproxyUsername());
        if (jimTest || jeffTest) {
            getClaims().put("DEBUG", "If you see this message, the server is in test mode!");
            getClaims().put("idp", "https://idp.fnal.gov/idp/shibboleth");
            getClaims().put("eppn", (jimTest ? "jbasney" : "jgaynor") + "@fnal.gov");
            DebugUtil.trace(this, "set debug claims for FNAL testing...");
        }


        // GITHub IDP
        //getClaims().put("idp","http://github.com/login/oauth/authorize");
        // getClaims().put("oidc","oidc-43455756756");

        // Google IDP
        //getClaims().put("idp","http://google.com/accounts/o8/id");
        // getClaims().put("oidc","oidc-43455756756");

    }
    // Enables IDP debugging for testing. Only have it set true for a specific test since it will override
    // the IDP information and identity for every request!!!


    @Override
    public void init() throws Throwable {
        claims = getClaims();
        trace(this, "Starting to process basic claims");
        if (IDP_DEBUG_ON) {
            addDebugClaims();
        }
        claims.put(OA2Claims.ISSUER, issuer);
        claims.put(OA2Claims.SUBJECT, transaction.getUsername());

        claims.put(AUDIENCE, transaction.getClient().getIdentifierString());
        claims.put(OA2Constants.ID_TOKEN_IDENTIFIER, ((OA2TokenForge) oa2se.getTokenForge()).getIDToken().getToken());
        // now set all the timestamps and such.
        setAccountingInformation();
        checkRequiredScopes(transaction);
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims.
            transaction.setUserMetaData(claims); // make sure this is available to the next handler
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
        transaction.setUserMetaData(claims); // make sure this is available to the next handler
    }

    @Override
    public void refreshAccountingInformation() {
        trace(this, "Refreshing the accounting information for the claims");
        if (0 < getPhCfg().getPayloadConfig().getLifetime()) {
            // CIL-708 fix: Make sure the refresh endpoint hands back the right expiration.
            getClaims().put(EXPIRATION, (getPhCfg().getPayloadConfig().getLifetime() + System.currentTimeMillis()) / 1000); // expiration is in SECONDS from the epoch.
        } else {
            getClaims().put(EXPIRATION, System.currentTimeMillis() / 1000 + 15 * 60); // expiration is in SECONDS from the epoch.
        }
        getClaims().put(ISSUED_AT, System.currentTimeMillis() / 1000); // issued at = current time in seconds.
    }


    @Override
    public void setAccountingInformation() {
        trace(this, "Setting the accounting information for the claims");
        if (transaction.getNonce() != null && 0 < transaction.getNonce().length()) {
            getClaims().put(NONCE, transaction.getNonce());
        }
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            // Fix CIL-906
            getClaims().put(AUTHORIZATION_TIME, transaction.getAuthTime().getTime() / 1000); // spec says this is an integer
        }
        refreshAccountingInformation();
    }


    @Override
    public void addRequestState(ScriptRunRequest req) throws Throwable {
        req.getArgs().put(SRE_REQ_CLAIMS, getClaims());
        req.getArgs().put(SRE_REQ_CLAIM_SOURCES, getSources()); // so its a map
        req.getArgs().put(SRE_REQ_EXTENDED_ATTRIBUTES, getExtendedAttributes()); // so its a map
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
                setClaims((JSONObject) resp.getReturnedValues().get(SRE_REQ_CLAIMS));
                sources = (List<ClaimSource>) resp.getReturnedValues().get(SRE_REQ_CLAIM_SOURCES);
                transaction.setClaimsSources(sources);
                extendedAttributes = (JSONObject) resp.getReturnedValues().get(SRE_REQ_EXTENDED_ATTRIBUTES);
                // Note that as per our contract, extended attributes are not updateable.
                return;
            case RC_NOT_RUN:
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
    public void finish(String execPhase) throws Throwable {
        // only required one by the spec. and only if the server is OIDC.
        if (oa2se.isOIDCEnabled()) {
            checkClaim(getClaims(), SUBJECT);
        }
    }

    @Override
    public void saveState() throws Throwable {
        DebugUtil.trace(this, ".saveState: claims = " + getClaims().toString(2));
        switch (getResponseCode()) {
            case RC_NOT_RUN:
                break;
            case RC_OK:
                if (transaction != null && oa2se != null) {
                    transaction.setUserMetaData(getClaims());
                    transaction.setClaimsSources(getSources());
                    DebugUtil.trace(this, ".saveState: done updating transaction.");
                }
            case RC_OK_NO_SCRIPTS:
                oa2se.getTransactionStore().save(transaction);
                break;

        }
/*        if (transaction != null && oa2se != null) {
            transaction.setUserMetaData(getClaims());
            transaction.setClaimsSources(getSources());
            oa2se.getTransactionStore().save(transaction);
            DebugUtil.trace(this, ".saveState: done saving transaction.");

        } else {
            trace(this, "In saveState: either env or transaction null. Nothing saved.");
        }*/
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
            throw new OA2RedirectableError(OA2Errors.INVALID_SCOPE,
                    "invalid scope: no open id scope",
                    HttpStatus.SC_UNAUTHORIZED,
                    t.getRequestState(),
                    t.getCallback());
        }
    }

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
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get more than basic claims.
            return claims;
        }
        return super.execute(source, claims);
    }


}
