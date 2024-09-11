package org.oa4mp.delegation.server;

import edu.uiuc.ncsa.security.core.configuration.Configurations;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.util.*;

import static org.oa4mp.delegation.server.OA2ConfigTags.*;
import static org.oa4mp.delegation.server.OA2Constants.SCOPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/26/15 at  3:59 PM
 */
public class OA2ConfigurationLoaderUtils extends XMLConfigUtil {

    /**
     * <p>To read a block of parameters from a (client) configuration. These are sent along with the
     * initial request. Format is
     * <pre>
     * &lt;parameters&gt;
     *    &lt;parameter key="key0" enabled=("true"|"false")&gt;value0&lt;/parameter&gt;
     *    &lt;parameter key="key1"&gt;value1&lt;/parameter&gt;
     *    ...
     * &lt;/parameters&gt;
     * </pre>
     * where the keys and values will be properly encoded (so you don't have to do it). These
     * will end up in the request as <code>...&amp;key0=value0&amp;key1=value1&amp;...</code>. Note that
     * the value sent is the body of the element, so you can literally send anything if you include it
     * in a CDATA tag.
     *
     * <p>
     * There is an <i>optional</i> flag to enable these. No flag means it is enabled. Disabling will
     * prevent it from being included. This allows you to turn on and off parameters in the file
     * without having to comment things out or remove them. Note that at this point, these are only
     * sent in the initial request.
     *
     * @param cn
     * @return
     */
    public static Map<String, List<String>> getAdditionalParameters(ConfigurationNode cn) {
//        if (params == null) {
        Map<String, List<String>> params = new HashMap<>();
        if (0 < cn.getChildrenCount(ADDITIONAL_PARAMETERS)) {
            ConfigurationNode node = Configurations.getFirstNode(cn, ADDITIONAL_PARAMETERS);
            List kids = node.getChildren(ADDITIONAL_PARAMETER);
            for (int i = 0; i < kids.size(); i++) {
                ConfigurationNode currentNode = (ConfigurationNode) kids.get(i);
                String x = Configurations.getFirstAttribute(currentNode, PARAMETER_KEY);

                if (x == null) {
                    continue; // no key means skip it!
                }
                String y = Configurations.getFirstAttribute(currentNode, SCOPE_ENABLED);
                boolean isEnabled = true; // default
                if (y != null) {
                    isEnabled = Boolean.parseBoolean(y);
                }
                if (isEnabled) {
                    List<String> values;
                    if (params.containsKey(x)) {
                        values = params.get(x);
                    } else {
                        values = new ArrayList<>();
                    }
                    // in case they leave a blank or two in the config.
                    values.add(((String) currentNode.getValue()).trim());
                    params.put(x, values);
                }

            }
        }

        //      }
        return params;
    }

    /**
     * The block containing the scopes. Format is  (there may be more, just add them)
     * <pre>
     *  &lt;scopes&gt;
     *      &lt;scope&gt;openid&lt;/scope&gt;
     *      &lt;scope&gt;email&lt;/scope&gt;
     *      &lt;scope enabled="false"&gt;edu.uiuc.ncsa.myproxy.getcert&lt;/scope&gt;
     *      &lt;scope&gt;profile&lt;/scope&gt;
     *      &lt;scope&gt;org.cilogon.userinfo&lt;/scope&gt;
     *  &lt;/scopes&gt;
     * </pre>
     * Each block has an <code>enabled</code> flag so you can turn these off and on without removing them.
     *
     * @param cn
     * @return
     */
    public static Collection<String> getScopes(ConfigurationNode cn) {
        //   if (scopes == null) {
        Collection<String> scopes = new HashSet<>(); // keep the elements unique
        // Fix https://github.com/ncsa/oa4mp/issues/103
        // First thing is to take all the basic scopes supported and include them.
/*
            for (String s : OA2Scopes.basicScopes) {
                scopes.add(s);
            }
*/
        if (0 < cn.getChildrenCount(SCOPES)) {
            // Then we have some scopes
            ConfigurationNode node = Configurations.getFirstNode(cn, SCOPES);
            List kids = node.getChildren(SCOPE);
            for (int i = 0; i < kids.size(); i++) {
                ConfigurationNode currentNode = (ConfigurationNode) kids.get(i);

                String currentScope = ((String) currentNode.getValue()).trim(); // in case they leave a blank or two in the config.
                String x = Configurations.getFirstAttribute(currentNode, SCOPE_ENABLED);
                if (x != null) {
                    boolean isEnabled = Boolean.parseBoolean(x);
                    if (isEnabled) {
                        scopes.add(currentScope);

                    } else {
                        scopes.remove(currentScope);
                    }
                } else {
                    // default is if the enabled flag is omitted, to assume it is enabled and add it.
                    scopes.add(currentScope);
                }
            }
        }
        // }
        return scopes;
    }



}
