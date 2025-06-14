package org.oa4mp.server.loader.oauth2.claims;

import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.server.server.claims.*;
import org.oa4mp.delegation.server.server.config.LDAPConfiguration;
import org.oa4mp.delegation.server.server.config.LDAPConfigurationUtil;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;

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
