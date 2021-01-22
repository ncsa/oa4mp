package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.security.util.configuration.TemplateUtil.*;

/**
 * Utilities for working with scopes. These are static since they will be used by QDL functions
 * for instance to make sure there is a single place with <b>ALL</b> the logic
 * and edge cases.
 * <p>Created by Jeff Gaynor<br>
 * on 1/21/21 at  10:32 AM
 */
public class ScopeTemplateUtil {
    public static Collection<String> doCompareTemplates(Collection<String> computedScopes,
                                                        Collection<String> requestedScopes,
                                                        boolean isTX) {
        Collection<String> returnedScopes = new HashSet<>();
        for (String r : requestedScopes) {
            if (!r.contains(":")) {
                // This is a quick and dirty check that the requested scope is a relative URI
                // we don't want to check, e.g. "profile" against all the stored templates.
                continue;
            }
            for (String c : computedScopes) {
                if (r.equals(c)) {
                    returnedScopes.add(c);
                } else {
                   /* If their lengths are the same, c can't be super-string of r.
                      Hard bit is that these are URIs and we have to make sure that
                      things like this are accounted for
                      c = x.y:/abc/def      (stored)
                      r = x.y:/abc/def/ghi  ok
                      r = x.y:/abc/defg     fail -- would grant access to different resource
                      So simple sub/super string comparisons fail here.
                   */
                    String x = compareAsURI(r, c, isTX);
                    if (x != null) {
                        returnedScopes.add(x);
                    }
                }
            }
        }
        return returnedScopes;
    }

    /**
     * There is a {@link URI#compareTo(URI)} method that is crap. This does it right.
     *
     * @param requestedScope
     * @param computedScope
     * @param isTX
     * @return
     */
    public static String compareAsURI(String requestedScope, String computedScope, boolean isTX) {
        try {
            //heads and tails must match. No fragments allowed
            // First special case, one of them is just a head, e.g. read: (asking for read scopes)
            // Can't make a URI out of that since there is no scheme specific part.
            if (isTX) {
                if (requestedScope.endsWith(":")) {
                    return null;
                }
                if (computedScope.endsWith(":")) {
                    if (requestedScope.startsWith(computedScope)) {
                        return requestedScope;
                    }
                    return null;
                }
            } else {
                if (requestedScope.endsWith(":")) {
                    if (computedScope.startsWith(requestedScope)) {
                        return computedScope;
                    }
                    // it will fail later in URI.create anyway.
                    return null;
                }
                if (computedScope.endsWith(":")) {
                    // Before this method, these two scopes were checked  if they were
                    // equal as strings, so there is no way these can match at this point
                    // if the computed scope ends with : and the request scope does too or not
                    // This is to prevent running through all the code below and failing at the
                    // last instant.
                    if (!isTX) {
                        // Case where initial token exchange is just asking for the scope it wants:
                        // E.g. requested = x.z:/any computed = x.z:
                        if (requestedScope.startsWith(computedScope)) {
                            return requestedScope;
                        }
                    }
                    return null;
                }
            }
            URI r = URI.create(requestedScope);
            if (!r.isAbsolute() || r.getFragment() != null) {
                return null;
            }

            URI c = URI.create(computedScope);
            if (!c.isAbsolute() || c.getFragment() != null) {
                return null;
            }

            if (!r.getScheme().equals(c.getScheme())) {
                return null;
            }

            if (r.getPort() != c.getPort()) {
                return null;
            }
            if (r.getQuery() != null && !r.getQuery().equals(c.getQuery())) {
                return null;
            }

            StringTokenizer base;
            StringTokenizer proposed;
            if (isTX) {
                base = new StringTokenizer(c.getPath(), "/");
                proposed = new StringTokenizer(r.getPath(), "/");
            } else {
                base = new StringTokenizer(r.getPath(), "/");
                proposed = new StringTokenizer(c.getPath(), "/");
            }
            // proposed is always a super URI of base. It cannot match if it has fewer components
            if (isTX && proposed.countTokens() < base.countTokens()) {
                return null;
            }
            // compare base has fewer tokens, so this loop should always work
            while (base.hasMoreTokens()) {
                String b = base.nextToken();
                if (proposed.hasMoreTokens()) {
                    String p = proposed.nextToken();
                    if (!b.equals(p)) {
                        return null;
                    }
                } else {
                    if (!isTX) {
                        // E.g. computed = x.y:/abc/def requested = x.y:/abc/def/ghi
                        // Case where in token call they actually request the scopes they want
                        // not a super set for querying what is there.
                        // So running out of components, is ok here.
                        return requestedScope;
                    }
                }
            }

        } catch (Throwable t) {
            return null;
        }
        if (isTX) {
            return requestedScope;
        }
        return computedScope;
    }

    /**
     * resolve a single template for groups (if any) and other claims.
     * Such a template would look like head:/path/${groupName} where the name of the
     * group is there. Any
     *
     * @param currentTemplate
     * @param groups
     */
    protected static List<String> replaceTemplate(String currentTemplate,
                                            Map<String, List<String>> groups,
                                            Map claimsNoGroups) {
        List<String> result = new ArrayList<>();
        if (groups.isEmpty() ) {
            result.add( simpleReplacement(currentTemplate, claimsNoGroups));
            return result;
        }
        // Do all simple, non-group replacements.
        currentTemplate = replaceAll(currentTemplate, claimsNoGroups);
        if(!currentTemplate.contains(LEFT_DELIMITER)){
            result.add(currentTemplate);
            return result;
        }
        // if there are no groups just return
        for(String key : groups.keySet()){
            String claimKey = LEFT_DELIMITER + key + RIGHT_DELIMITER;
            List<String> groupNames = groups.get(key);
            if (currentTemplate.contains(claimKey)) {
               for(String groupName : groupNames){
                      String newPath = currentTemplate.replace(claimKey, groupName);
                   result.add(simpleReplacement(newPath, claimsNoGroups));
               }
            }
        }
        return result;

    }

    protected static String simpleReplacement(String currentTemplate, Map claims) {
        return replaceAll(currentTemplate, claims);
    }

}
