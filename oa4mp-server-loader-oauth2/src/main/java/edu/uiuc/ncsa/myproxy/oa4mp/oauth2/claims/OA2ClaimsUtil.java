package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.AUTHORIZATION_TIME;
import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.NONCE;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/24/18 at  11:13 AM
 */
public class OA2ClaimsUtil {
    OA2ServiceTransaction transaction;
    OA2SE oa2se;

    public OA2ClaimsUtil(OA2SE oa2se, OA2ServiceTransaction transaction) {
        this.oa2se = oa2se;
        this.transaction = transaction;
    }


    public JSONObject createBasicClaims(HttpServletRequest request) throws Throwable {
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get claims.
            return new JSONObject();
        }

        JSONObject claims = transaction.getClaims();
        if (claims == null) {
            claims = new JSONObject();
            claims.put("foo", "bar");
        }

        DebugUtil.dbg(this, "Starting to process basic claims");
        String issuer = null;
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
        claims.put(OA2Claims.ISSUER, issuer);

        claims.put(OA2Claims.SUBJECT, transaction.getUsername());
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        if (transaction.getNonce() != null && 0 < transaction.getNonce().length()) {
            claims.put(NONCE, transaction.getNonce());
        }
        if (transaction.hasAuthTime()) {
            // convert the date to a time if needed.
            claims.put(AUTHORIZATION_TIME, Long.toString(transaction.getAuthTime().getTime() / 1000));
        }
        claims.put(AUDIENCE, transaction.getClient().getIdentifierString());
        claims.put(EXPIRATION, System.currentTimeMillis() / 1000 + 15 * 60); // expiration is in SECONDS from the epoch.
        claims.put(ISSUED_AT, System.currentTimeMillis() / 1000); // issued at = current time in seconds.
        transaction.setClaims(claims);
        DebugUtil.dbg(this, "Done with basic claims = " + claims);
        DebugUtil.dbg(this, "Starting to process server default claims");

        if (oa2se != null && oa2se.getClaimSource() != null && oa2se.getClaimSource().isEnabled() && oa2se.getClaimSource().isRunAtAuthorization()) {
            DebugUtil.dbg(this, "Service environment has a claims source enabled=" + oa2se.getClaimSource());

            // allow the server to pre-populate the claims. This invokes the global claims handler for the server
            // to allow, e.g. pulling user information out of HTTp headers.
            oa2se.getClaimSource().process(claims, request, transaction);
        } else {
            DebugUtil.dbg(this, "Service environment has a claims no source enabled during authorization");
        }

        DebugUtil.dbg(this, "Starting to process Client runtime and sources at authorization.");

        OA2Client client = getOA2Client();


        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            // no configuration for this client means do nothing here.
            return claims;
        }
        // so this client has a specific configuration that is to be invoked.
        if (!getCC().isSaved()) {
            getCC().setSaved(true); // do this so it ends up in storage as saved, otherwise it gets saved every time.
            // This means that the configuration was updated on load and needs to be saved.
            oa2se.getClientStore().save(client);
        }
        DebugUtil.dbg(this, "executing runtime");

        getCC().executeRuntime();
        DebugUtil.dbg(this, "processing flows");

        FlowStates flowStates = new FlowStates(getCC().getRuntime().getFunctorMap());
        transaction.setFlowStates(flowStates);
        if (flowStates.getClaims) {
            DebugUtil.dbg(this, "Doing preprocessing");
            DebugUtil.dbg(this, "Claims allowed, creating sources from configuration");
            OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(getFF());
            OA2ClientConfiguration oa2CC = getCC();

            ff.createClaimSource(oa2CC, client.getConfig());
            // the runtime forbids processing claims for this request, so exit
            doPreProcessing();
            List<ClaimSource> claimsSources = oa2CC.getClaimSource();
            if (oa2CC.hasClaimSource()) {
                // so there is
                for (int i = 0; i < claimsSources.size(); i++) {
                    ClaimSource claimSource = claimsSources.get(i);
                    if (claimSource.isRunAtAuthorization())
                        claimSource.process(claims, request, transaction);
                    if(claimSource.getPostProcessor()!=null) {
                        flowStates.updateValues(claimSource.getPostProcessor().getFunctorMap());
                    }
                    if(!flowStates.acceptRequests){
                        // This practically means that the come situation has arisen whereby the user is
                        // immediately banned from access -- e.g. they were found to be on a blacklist.
                        transaction.setClaims(claims);
                        transaction.setFlowStates(flowStates);
                        oa2se.getTransactionStore().save(transaction);
                        throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED);
                    }
                    DebugUtil.dbg(this, "user info for claim source #" + claimSource + " = " + claims);
                }
            }

        }
        // save it at this point because the flow states might, e.g. prohibit access to the entire system
        // and that has to be preserved against future access attempts.
        transaction.setClaims(claims);
        transaction.setFlowStates(flowStates);
        oa2se.getTransactionStore().save(transaction);
        return claims;
    }

    protected OA2Client getOA2Client() {
        return transaction.getOA2Client();
    }

    OA2ClientConfiguration cc = null;

    OA2FunctorFactory ff = null;

    protected OA2FunctorFactory getFF() {
        if (ff == null) {
            ff = new OA2FunctorFactory(transaction.getClaims());

        }
        return ff;
    }

    protected OA2ClientConfiguration getCC() {
        if (cc == null && null != getOA2Client().getConfig()) {

            OA2FunctorFactory functorFactory = getFF();
            OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(functorFactory);

            cc = ff.newInstance(getOA2Client().getConfig());
        }
        return cc;
    }

    public JSONObject createSpecialClaims() throws Throwable {
        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get claims.
            return new JSONObject();
        }

        JSONObject claims = transaction.getClaims();
        if (claims == null) {
            claims = new JSONObject();
        }
        FlowStates flowStates = transaction.getFlowStates();
        // save everything up to this point since there are no guarantees that processing will continue:
        if (!flowStates.acceptRequests) {
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED);
        }
        OA2Client client = getOA2Client();

        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            // no configuration for this client means do nothing here.
            return claims;
        }
        // so this client has a specific configuration that is to be invoked.
        OA2ClientConfiguration oa2CC = getCC();

        DebugUtil.dbg(this, "BEFORE invoking claim sources, claims are = " + claims);
        if (flowStates.getClaims) {
            DebugUtil.dbg(this, "Claims allowed, creating sources from configuration");
            OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(getFF());

            ff.createClaimSource(oa2CC, client.getConfig());
            // the runtime forbids processing claims for this request, so exit
            List<ClaimSource> claimsSources = oa2CC.getClaimSource();
            if (oa2CC.hasClaimSource()) {
                // so there is
                for (int i = 0; i < claimsSources.size(); i++) {
                    ClaimSource claimSource = claimsSources.get(i);
                    if (!claimSource.isRunAtAuthorization()) {
                        claimSource.process(claims, transaction);
                        DebugUtil.dbg(this, "After invoking claim source, new claims = " + claims);
                    }
                }
            }

        }
        // these might have changed in the course of executing the claim source.
        DebugUtil.dbg(this, "Ready for post-processing");
        doPostProcessing();
        // Now we have to set up the claims sources and process the results
        // last thing is to check that the flow states did not change as a result of claims processing
        // e.g. that the user membership in a group changes access
        flowStates = transaction.getFlowStates();
        flowStates.updateValues(oa2CC.getPostProcessing().getFunctorMap());

        // update everything
        transaction.setFlowStates(flowStates);
        transaction.setClaims(claims);// since the JSON library tends to clone things and they go missing, just set it again.
        oa2se.getTransactionStore().save(transaction);
        DebugUtil.dbg(this, "Done with special claims=" + claims);
        // After post-processing it is possible that this user should be forbidden access, e.g. they are not in the correct group.
        // This is the first place we can check. If they are not allowed to make further requests, an access denied exception is thrown.
        if(!flowStates.acceptRequests){
            DebugUtil.dbg(this, "Access denied for user name =" + transaction.getUsername());

            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED);
        }
        return claims;
    }

    /**
     * This is the post-processing after <b>ALL</b> the claim sources have run, should there be any. It is different
     * from the per-source processing.
     *
     * @throws Throwable
     */
    public void doPostProcessing() throws Throwable {
        DebugUtil.dbg(this, ".doPostProcessing: has post-processing?" + getCC().hasPostProcessing());
        if (getCC().hasPostProcessing()) {
            DebugUtil.dbg(this, ".doPostProcessing: has post-processing?" + getCC().getPostProcessing());

            OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(getFF());
            ff.setupPostProcessing(getCC(), getOA2Client().getConfig());
            getCC().executePostProcessing();
            DebugUtil.dbg(this, ".doPostProcessing: executed post-processing, functor map=" + getCC().getPostProcessing().getFunctorMap());

        }


    }

    /**
     * This is the pre-processing before <b>ALL</b> the claim sources have run, should there be any. It is different
     * from the per-source processing.
     *
     * @throws Throwable
     */

    public void doPreProcessing() throws Throwable {
        if (getCC().hasPreProcessing()) {
            OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(getFF());
            ff.setupPreProcessing(getCC(), getOA2Client().getConfig());
            getCC().executePreProcessing();
        }

    }
}
