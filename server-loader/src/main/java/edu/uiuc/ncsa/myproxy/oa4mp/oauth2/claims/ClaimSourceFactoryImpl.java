package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientFunctorScriptsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.*;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.LinkedList;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/16/16 at  3:08 PM
 */
public class ClaimSourceFactoryImpl extends ClaimSourceFactory {

    public ClaimSourceFactoryImpl() {
    }

    @Override
    public ClaimSource create(ClaimSourceFactoryRequest request) {
        if (request instanceof LDAPClaimSourceFactoryRequest) {
            ServletDebugUtil.trace(this, ".create: request = " + request);
            LDAPClaimSourceFactoryRequest req = (LDAPClaimSourceFactoryRequest) request;
            LDAPClaimsSource h = new LDAPClaimsSource(req.getLdapConfiguration(), req.getLogger());
            h.setScopes(req.getScopes());
            return h;
        }
        BasicClaimsSourceImpl h = new BasicClaimsSourceImpl();
        h.setConfiguration(request.getConfiguration());
        h.setScopes(request.getScopes());
        return h;
    }

    /**
     * This creates a uniform list of claim sources for both the access token servlet and the user info servlet.
     * It will use a common handler if there is one and use the configured factory to create appropriate ones
     * (and populate them with the right runtime environment otherwise.
     *
     * @param oa2SE
     * @param transaction
     * @return
     */
    public static LinkedList<ClaimSource> createClaimSources(OA2SE oa2SE, OA2ServiceTransaction transaction) {
        DebugUtil.trace(ClaimSourceFactoryImpl.class, "Starting to create LDAPScopeHandlers per client");
        LinkedList<ClaimSource> claimSources = new LinkedList<>();
        JSONObject jsonConfig = ((OA2Client)transaction.getClient()).getConfig();
        if (!OA2ClientFunctorScriptsUtil.hasClaimSourceConfigurations(jsonConfig)) {
            DebugUtil.trace(ClaimSourceFactoryImpl.class, "using default scope handler=");
            if (oa2SE.getClaimSource() instanceof BasicClaimsSourceImpl) {
                BasicClaimsSourceImpl bb = (BasicClaimsSourceImpl) oa2SE.getClaimSource();
                if (bb.getOa2SE() == null) {
                    DebugUtil.trace(ClaimSourceFactoryImpl.class, "setting scope handler environment #1");
                    bb.setOa2SE(oa2SE);
                }
            }
            claimSources.add(oa2SE.getClaimSource());
        } else {
            JSONArray configs = OA2ClientFunctorScriptsUtil.getClaimSourceConfigurations(jsonConfig);

            for (int i = 0; i < configs.size(); i++) {
                JSONObject current = configs.getJSONObject(i);
                ClaimSource c = null;
                LDAPConfigurationUtil ldapConfigurationUtil = new LDAPConfigurationUtil();
                ClaimSourceConfigurationUtil claimSourceConfigurationUtil = new ClaimSourceConfigurationUtil();
                if (ldapConfigurationUtil.isInstanceOf(current)) {
                    c = processLDAPConfig(ldapConfigurationUtil,
                            current,
                            oa2SE,
                            transaction);

                }
                if (claimSourceConfigurationUtil.isInstanceOf(current)) {
                    c = processDefaultConfig(claimSourceConfigurationUtil,
                            current,
                            oa2SE,
                            transaction);
                }
                if (c != null) {
                    claimSources.add(c);
                }

            }
        }
        return claimSources;
    }


    protected static ClaimSource processDefaultConfig(ClaimSourceConfigurationUtil claimSourceConfigurationUtil,
                                                      JSONObject json,
                                                      OA2SE oa2SE,
                                                      OA2ServiceTransaction transaction) {

        ClaimSourceConfiguration cfg = claimSourceConfigurationUtil.fromJSON(null, json);
        DebugUtil.trace(ClaimSourceFactoryImpl.class, "Got default configuration for server id=" + cfg.getId() + ", name=" + cfg.getName());
        ClaimSourceFactoryRequest req = new ClaimSourceFactoryRequest(oa2SE.getMyLogger(), cfg, transaction.getScopes());
        ClaimSource claimSource = ClaimSourceFactory.newInstance(req);
        DebugUtil.trace(ClaimSourceFactoryImpl.class, "creating claim source, claims Source=  " + claimSource);
        DebugUtil.trace(ClaimSourceFactoryImpl.class, "  , OA2SE  " + oa2SE);
        if (claimSource instanceof BasicClaimsSourceImpl) {
            ((BasicClaimsSourceImpl) claimSource).setOa2SE(oa2SE);
        }
        return claimSource;
    }

    protected static ClaimSource processLDAPConfig(LDAPConfigurationUtil ldapConfigurationUtil,
                                                   JSONObject json,
                                                   OA2SE oa2SE,
                                                   OA2ServiceTransaction transaction) {
        LDAPConfiguration cfg = ldapConfigurationUtil.fromJSON(json);
        DebugUtil.trace(ClaimSourceFactoryImpl.class, "Got LDAP configuration for server " + cfg.getServer());
        LDAPClaimSourceFactoryRequest req = new LDAPClaimSourceFactoryRequest(oa2SE.getMyLogger(),
                cfg, transaction.getScopes());
        ClaimSource claimSource = ClaimSourceFactory.newInstance(req);
        if (claimSource instanceof BasicClaimsSourceImpl) {
            DebugUtil.trace(ClaimSourceFactoryImpl.class, "Scope handler\"" + claimSource.getClass().getSimpleName() + "\" is configured.");

            ((BasicClaimsSourceImpl) claimSource).setOa2SE(oa2SE);
            DebugUtil.trace(ClaimSourceFactoryImpl.class, "setting scope handler environment #2");
        }
        return claimSource;
    }


}
