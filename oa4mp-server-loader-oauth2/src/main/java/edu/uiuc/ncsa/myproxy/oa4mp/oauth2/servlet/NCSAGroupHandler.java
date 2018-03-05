package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.scopeHandlers.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.scopeHandlers.Groups;
import net.sf.json.JSONArray;

import java.util.StringTokenizer;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:48 PM
 */
public class NCSAGroupHandler extends GroupHandler {
    /**
     * The form of an LDAP record is cn=group,buncha stuff.
     *
     * @param jsonArray
     * @return
     */
    @Override
    public Groups parse(JSONArray jsonArray) {
        Groups groups = new Groups();
        for (Object x : jsonArray) {
            if (x instanceof String) {
                StringTokenizer st = new StringTokenizer(x.toString(), ",");
                while (st.hasMoreTokens()) {
                    String nextToken = st.nextToken();
                    if (nextToken.startsWith("cn=")) {
                        nextToken = nextToken.substring(3);
                        GroupElement g = new GroupElement(nextToken);
                        groups.put(g);
                    }
                }
            }
        }
        return groups;
    }
}
