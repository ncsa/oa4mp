package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.configuration.TemplateUtil;

import java.util.*;

/**
 * This will take a template (which is just a string with wildcards and a few other items) and resolve it against a given target.
 * <br/>
 * E.g. if the template is
 * <pre>
 *    a/b/c/${user}/data/**
 * </pre>
 * and the target is
 * <pre>
 *     a/b/c/bob/data/file.dat
 * </pre>
 * then this would resolve true if the user is named "bob" and fail otherwise.
 * <p>Created by Jeff Gaynor<br>
 * on 9/11/18 at  6:08 PM
 */
public class OldTemplateResolver {


    /**
     * @param authorizationTemplates
     * @param audience               The requested audience
     * @param scopes                 The requested scope in claims format.
     * @return
     */
    public List<String> resolve(AuthorizationTemplates authorizationTemplates,
                                String audience,
                                Collection<String> scopes) {
        LinkedList<String> returnedScopes = new LinkedList<>();

        for (String key : authorizationTemplates.keySet()) {
            if (check(key, audience)) {
                // so the audience checks out.
                // now to sort out the scopes.
                for (String scope : scopes) {
                    String[] parts = scope.split(":");
                    if (1 == parts.length) {
                        //throw new NFWException("Error: no operation is included with this scope request");
                        ServletDebugUtil.trace(this, "No operation found for scope request \"" + scope + "\", with audience = \"" + audience + "\"");
                        return returnedScopes;
                    }
                    String operation = parts[0];
                    String path = parts[1];
                    AuthorizationTemplate authorizationTemplate = authorizationTemplates.get(key);
                    for (AuthorizationPath authorizationPath : authorizationTemplate.getPaths()) {
                        if (operation.equals(authorizationPath.operation)) {
                            if (check(authorizationPath.path, path)) {
                                returnedScopes.add(operation + ":" + path);
                            }
                        }
                    }

                }
            }
        }
        return returnedScopes;
    }


    public OldTemplateResolver(String username, Groups group) {
        this.group = group;
        this.username = username;
    }

    String username = null;
    Groups group = null;


    public static final String ST_GROUP_NAME = "group";
    public static final String ST_USER_NAME = "user";

    protected boolean hasGroups() {
        return group != null && !group.isEmpty();
    }

    protected boolean hasUsername() {
        return username != null;
    }

    /**
     * The template is stored in the configuration. The target is the actual scope passed in by the client in the
     * request.
     * @param template
     * @param target
     * @return
     */
    public boolean check(String template, String target) {
        DebugUtil.trace(this, "testing " + target + " against template " + template);
        ArrayList<String> tests = new ArrayList<>();
        boolean un = template.contains("${" + ST_USER_NAME + "}");
        if (template.contains("${" + ST_GROUP_NAME + "}")) {
            // do replacements
            // There may be templates configured, but no groups for the user, depending on the IDP.
            // In the case, skip all of this
            if (hasGroups()) {
                for (String key : group.keySet()) {
                    HashMap<String, String> group = new HashMap<>();
                    group.put(ST_GROUP_NAME, key);
                    if (hasUsername() && un) {
                        group.put(ST_USER_NAME, username);
                    }
                    String replacedString = TemplateUtil.replaceAll(template, group);
                    DebugUtil.trace(this, template + " --> " + replacedString);
                    tests.add(replacedString);
                }
            }


        } else {
            if (un) {
                // replace username but there are no groups.
                HashMap<String, String> group = new HashMap<>();
                group.put(ST_USER_NAME, username);
                tests.add(TemplateUtil.replaceAll(template, group));
            } else {
                // so no replacements. Just put in the template.
                tests.add(template);
            }
            // no groups, single
        }
        for (String template1 : tests) {
            DebugUtil.trace(this, "   testing: " + template1 + ", username = " + username);
            if (template1.endsWith("/**")) {
                // implies sub paths, not substrings, so /foo/** implies /foo, /foo/ and /foo/baz are ok,
                // but /foobar is not
                String noStars = null;
                String r = target.toString();
                if (!r.endsWith("/")) {
                    // normalize it a bit
                    r = r + "/";
                }
                noStars = template1.substring(0, template1.length() - 2); // keep trailing slash
                if (r.startsWith(noStars)) {
                    DebugUtil.trace(this, "   testing: returning " + target);
                    return true;
                }
            } else {
                if (template1.equals(target.toString())) {
                    DebugUtil.trace(this, "   testing: returning " + target);
                    return true;
                }
            }
        }
        System.err.println("   testing: returning false");

        return false;
    }

}
