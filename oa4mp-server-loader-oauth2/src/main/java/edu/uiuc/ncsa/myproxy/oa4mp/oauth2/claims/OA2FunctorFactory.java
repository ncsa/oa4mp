package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.flows.*;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;
import edu.uiuc.ncsa.security.util.functor.JFunctor;
import edu.uiuc.ncsa.security.util.functor.JFunctorFactory;
import net.sf.json.JSONObject;

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
    public OA2FunctorFactory(Map<String, Object> claims) {
        this.claims = claims;
    }

    protected Map<String, Object> claims;


    public boolean hasClaims() {
        return claims != null;
    }

    @Override
    protected String preprocess(String x) {
        return TemplateUtil.replaceAll(x, claims);
    }

    @Override
    protected JFunctor figureOutFunctor(JSONObject rawJson) {
        JFunctor ff = super.figureOutFunctor(rawJson);
        if (ff != null) {
            // already got one.
            return ff;
        }
        if (hasEnum(rawJson, IS_MEMBER_OF)) {
            ff = new jIsMemberOf(claims);
        }
        if (hasEnum(rawJson, EXCLUDE)) {
            ff = new jExclude(claims);
        }
        if (hasEnum(rawJson, INCLUDE)) {
            ff = new jInclude(claims);
        }
        if (hasEnum(rawJson, SET)) {
            ff = new jSet(claims);
        }
        if (hasEnum(rawJson, FlowType.ACCEPT_REQUESTS)) {
            ff = new jAcceptRequests();
        }
        if (hasEnum(rawJson, FlowType.ACCESS_TOKEN)) {
            ff = new jAccessToken();
        }

        if (hasEnum(rawJson, GET_CERT)) {
            ff = new jGetCert();
        }

        if (hasEnum(rawJson, FlowType.ID_TOKEN)) {
            ff = new jIDToken();
        }
        if (hasEnum(rawJson, FlowType.REFRESH_TOKEN)) {
            ff = new jRefreshToken();
        }

        if (hasEnum(rawJson, FlowType.USER_INFO)) {
            ff = new jUserInfo();
        }
        if (hasEnum(rawJson, FlowType.SET_CLAIM_SOURCE)) {
            ff = new jSetClaimSource();
        }
        return ff;
    }
}
