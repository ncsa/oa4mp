package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.*;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.FunctorClaimsType.*;
import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.FlowType.GET_CERT;

/**
 * A Claims Aware functor factory. This will replace templates with their values
 * based on the claims supplied in a hashmap.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  10:09 AM
 */
public class OA2FunctorFactory extends JFunctorFactory {
    public OA2FunctorFactory(Map<String, Object> claims, Collection<String> scopes) {
        this.claims = claims;
        this.scopes = scopes;
    }

    protected Map<String, Object> claims;

    @Override
    public Map<String, String> getReplacementTemplates() {
        HashMap<String, String> templates = new HashMap<>();
        templates.putAll(getEnvironment());
        if (claims != null) {
            for (String key : claims.keySet()) {
                templates.put(key, claims.get(key).toString());
            }
        }
        return templates;
    }

    public boolean hasClaims() {
        return claims != null;
    }

    public Collection<String> getScopes() {
        return scopes;
    }

    Collection<String> scopes;

    @Override
    protected String preprocess(String x) {
        return TemplateUtil.replaceAll(x, claims);
    }

    @Override
    public JFunctor lookUpFunctor(String name) {
        JFunctor functor = super.lookUpFunctor(name);
        if (functor != null) {
            return functor;
        }
        if (name.equals(IS_MEMBER_OF.getValue())) {
            return new jIsMemberOf(claims);
        }
        if (name.equals(EXCLUDE.getValue())) {
            return new jExclude(claims);
        }
        if (name.equals(HAS_SCOPE.getValue())) {
            return new jhasScope(getScopes());
        }
        if (name.equals(HAS_CLAIM.getValue())) {
            return new jHasClaim(claims);
        }
        if (name.equals(INCLUDE.getValue())) {
            return new jInclude(claims);
        }
        if (name.equals(RENAME.getValue())) {
            return new jRename(claims);
        }
        if (name.equals(SET.getValue())) {
            return new jSet(claims);
        }
        if (name.equals(GET.getValue())) {
            return new jGet(claims);
        }
        if (name.equals(FlowType.ACCEPT_REQUESTS.getValue())) {
            return new jAcceptRequests();
        }
        if (name.equals(FlowType.ACCESS_TOKEN.getValue())) {
            return new jAccessToken();
        }

        if (name.equals(GET_CERT.getValue())) {
            return new jGetCert();
        }

        if (name.equals(FlowType.ID_TOKEN.getValue())) {
            return new jIDToken();
        }
        if (name.equals(FlowType.REFRESH_TOKEN.getValue())) {
            return new jRefreshToken();
        }

        if (name.equals(FlowType.USER_INFO.getValue())) {
            return new jUserInfo();
        }
        if (name.equals(FlowType.SET_CLAIM_SOURCE.getValue())) {
            return new jSetClaimSource();
        }
        if (name.equals(FlowType.GET_CLAIMS.getValue())) {
            return new jGetClaims();
        }
        return null;
    }
}
