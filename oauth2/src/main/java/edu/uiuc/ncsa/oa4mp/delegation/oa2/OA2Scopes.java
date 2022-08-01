package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/15 at  2:04 PM
 */
public interface OA2Scopes {
    String SCOPE_ADDRESS = "address";
    String SCOPE_EMAIL = "email";
    String SCOPE_MYPROXY = "edu.uiuc.ncsa.myproxy.getcert";
    String SCOPE_OFFLINE_ACCESS = "offline_access";
    String SCOPE_OPENID = "openid";
    String SCOPE_PHONE = "phone";
    String SCOPE_PROFILE = "profile";
    String EDU_PERSON_ORC_ID = "eduPersonOrcid";
    String SCOPE_CILOGON_INFO = "org.cilogon.userinfo";
    // CIL-771
    String SCOPE_CILOGON_TOKEN_MANAGER = "org.cilogon.tokenmanager ";


    /**
     * These are the basic scopes supported by the OA4MP OIDC protocol.
     */
    String[] basicScopes = {SCOPE_EMAIL,SCOPE_MYPROXY, SCOPE_CILOGON_INFO, SCOPE_OPENID, SCOPE_PROFILE};


    /**
     * Utility that checks if a given scope is allowed by the protocol. The scopes in this interface
     * are all potentially supported by a server. Basic support only requires that the open id scope be
     * present.
     */
    class ScopeUtil {
        public static Collection<String> getScopes() {
            return scopes;
        }

        public static void setScopes(Collection<String> scopes) {
            ScopeUtil.scopes = scopes;
        }

        static Collection<String> scopes;

        public static boolean hasScope(String targetScope){
            for(String x : getScopes()){
                if(x.equals(targetScope)) return true;
            }
            return false;
        }

    }
}
