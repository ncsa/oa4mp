package org.oa4mp.delegation.server;

import java.util.Arrays;
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
        protected static Collection<String> bList = null;

        public static Collection<String> getBasicScopes() {
            if (bList == null) {
                bList = Arrays.asList(basicScopes);
            }
            return bList;
        }

        /**
         * If the set of scopes for this instance of OA4MP are not standard, inject them.
         * @param scopes
         */
        public static void setBasicScopes(Collection<String> scopes) {
            bList = scopes;
        }

        public static Collection<String> intersection(Collection<String> x, Collection<String> y) {
            HashSet<String> x0 = new HashSet<>();
            x0.addAll(x);
            HashSet<String> y0 = new HashSet<>();
            y0.addAll(y);
            x0.retainAll(y0);
            return x0;
        }

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

        /**
         * Given a scope collection, turn it into a blank delimited string.
         *
         * @param scopes
         * @return
         */
        public static String toString(Collection<String> scopes) {
            String ss = "";
            if (!scopes.isEmpty()) {
                boolean firstPass = true;
                for (String s : scopes) {
                    ss = ss + (firstPass ? "" : " ") + s;
                    if (firstPass) {
                        firstPass = false;
                    }
                }
            }
            return ss;
        }
    }


}
