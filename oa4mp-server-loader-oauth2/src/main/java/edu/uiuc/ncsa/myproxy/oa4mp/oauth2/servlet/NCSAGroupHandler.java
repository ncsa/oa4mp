package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.LDAPClaimsSource;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import net.sf.json.JSONArray;

import javax.naming.NamingException;
import javax.naming.ldap.LdapContext;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:48 PM
 */
public class NCSAGroupHandler extends GroupHandler {
    public NCSAGroupHandler(LDAPClaimsSource claimsSource) {
        this.claimsSource = claimsSource;
    }

    LDAPClaimsSource claimsSource;

    public NCSAGroupHandler(LdapContext ctx) {
        this.ctx = ctx;
    }

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
                String xx = (String) x;
                int start = xx.indexOf("cn=");
                if (start != -1) {
                    int end = xx.indexOf(",", start);
                    String groupName = xx.substring(start + 3, end);
                    int gid = 0;
                    try {
                        gid = getGroupID(groupName);
                    } catch (NamingException e) {
                        e.printStackTrace();
                    }
                    GroupElement g = null;
                    if (gid == -1) {
                        // no gid
                        g = new GroupElement(groupName);
                    } else {
                        g = new GroupElement(groupName, gid);
                    }
                    groups.put(g);
                }

            }
        }
        return groups;
    }

    LdapContext ctx;
    public synchronized int getGroupID(String groupName) throws NamingException {
        try {
            return LDAPClaimsSource.getGid(claimsSource.getCfg(), groupName);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
        return -1;
    }
}
