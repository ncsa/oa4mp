package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import java.util.Collection;
import java.util.HashSet;
import java.util.StringTokenizer;

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
    // fix for https://github.com/ncsa/oa4mp/issues/112
    String SCOPE_USER_INFO = "org.oa4mp:userinfo";
    // CIL-771
    String SCOPE_TOKEN_MANAGER = "org.oa4mp:tokenmanager ";


    /**
     * These are the basic scopes supported by the OA4MP OIDC protocol.
     */
    String[] basicScopes = {SCOPE_EMAIL, SCOPE_MYPROXY, SCOPE_USER_INFO, SCOPE_CILOGON_INFO, SCOPE_OPENID, SCOPE_PROFILE};
    String[] nonPublicScopes = {SCOPE_EMAIL, SCOPE_MYPROXY, SCOPE_CILOGON_INFO, SCOPE_PROFILE};


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

        public static boolean hasScope(String targetScope) {
            for (String x : getScopes()) {
                if (x.equals(targetScope)) return true;
            }
            return false;
        }

        /**
         * return a collection from the given string of scopes. note that this applies the specification to
         * parse the string, so all scopes are blank delimited.
         *
         * @param x
         * @return
         */
        public static Collection<String> toScopes(String x) {
            HashSet<String> out = new HashSet<>(); // ensures uniqueness
            StringTokenizer st = new StringTokenizer(x, " ");
            while (st.hasMoreTokens()) {
                out.add(st.nextToken());
            }
            return out;

        }
    }


}
