package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowStates;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2DiscoveryServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfiguration;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.oauth_2_0.OA2GeneralError;
import edu.uiuc.ncsa.security.oauth_2_0.UserInfo;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimsUtil;
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
public class OA2ClaimsUtil extends ClaimsUtil {
    OA2ServiceTransaction transaction;
    OA2SE oa2se;

    public OA2ClaimsUtil(OA2SE oa2se, OA2ServiceTransaction transaction) {
        this.oa2se = oa2se;
        this.transaction = transaction;
    }

    @Override
    public JSONObject createClaims(HttpServletRequest request) throws Throwable {
        JSONObject claims = new JSONObject();

        if (transaction.getOA2Client().isPublicClient()) {
            // Public clients do not get claims.
            return claims;
        }
        claims = createBasicClaims(request, claims);
        claims = createSpecialClaims(request, claims);
        return claims;
    }

    /**
     * This peels the claims off the request (such as the nonce) and the client configuration.
     *
     * @param request
     * @param claims
     * @return
     */

    @Override
    protected JSONObject createBasicClaims(HttpServletRequest request, JSONObject claims) throws Throwable {

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
        UserInfo userInfo = new UserInfo();
        userInfo.setMap(claims);
        if (oa2se.getClaimSource().isEnabled()) {
            // allow the server to pre-populate the claims. This invokes the global claims handler for the server
            // to allow, e.g. pulling user information out of HTTp headers.
            oa2se.getClaimSource().process(userInfo, request, transaction);
        }
        return (JSONObject) userInfo.getMap();
    }

    @Override
    protected JSONObject createSpecialClaims(HttpServletRequest httpServletRequest, JSONObject claims) throws Throwable {
        OA2Client client = transaction.getOA2Client();

        // set up functor factory with no claims since we have none yet.
        //        Map<String, Object> claims = new HashMap<>();
        UserInfo userInfo = new UserInfo();
        userInfo.setMap(claims);

        if (client.getConfig() == null || client.getConfig().isEmpty()) {
            // no configuration for this client means do nothing here.
            return claims;
        }
        // so this client has a specific configuration that is to be invoked.
        OA2FunctorFactory functorFactory = new OA2FunctorFactory(userInfo.getMap());
        OA2ClientConfigurationFactory<OA2ClientConfiguration> ff = new OA2ClientConfigurationFactory(functorFactory);

        OA2ClientConfiguration oa2CC = ff.newInstance(client.getConfig());
        if(!oa2CC.isSaved()){
            // This means that the configuration was updated on load and needs to be saved.
            oa2se.getClientStore().save(client);
            oa2CC.setSaved(true);
        }
        oa2CC.executeRuntime();
        FlowStates flowStates = new FlowStates(oa2CC.getRuntime().getFunctorMap());
        transaction.setFlowStates(flowStates);
        // save it at this point because the flow states might, e.g. prohibit access to the entire system
        // and that has to be preserved against future access attempts.
        oa2se.getTransactionStore().save(transaction);
        // save everything up to this point since there are no guarantees that processing will continue:
        if(!flowStates.acceptRequests){
            throw new OA2GeneralError(OA2Errors.ACCESS_DENIED, "access denied", HttpStatus.SC_UNAUTHORIZED);
        }
        if (flowStates.getClaims) {
            ff.createClaimSource(oa2CC, client.getConfig());
            // the runtime forbids processing claims for this request, so exit
            List<ClaimSource> claimsSources = oa2CC.getClaimSource();
            if (oa2CC.hasClaimSource()) {
                // so there is
                for (int i = 0; i < claimsSources.size(); i++) {
                    claimsSources.get(i).process(userInfo, httpServletRequest, transaction);
                    System.err.println(userInfo.getMap());
                }
            }
            if (oa2CC.hasClaimsProcessing()) {
                ff.setupClaimsProcessing(oa2CC, client.getConfig());
                oa2CC.executeProcessing();
            }
        }
        // Now we have to set up the claims sources and process the results
        // last thing is to check that the flow states did not change as a result of claims processing
        // e.g. that the user membership in a group changes access
        flowStates.setValues(oa2CC.getProcessing().getFunctorMap());

        // update everything
        transaction.setFlowStates(flowStates);
        JSONObject jsonClaims = new JSONObject();
        jsonClaims.putAll(userInfo.getMap());
        transaction.setClaims(jsonClaims);
        oa2se.getTransactionStore().save(transaction);
        return jsonClaims;
    }

}
