package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.loader.oauth2.claims.Groups;
import org.oa4mp.server.loader.oauth2.claims.LDAPClaimsSource;
import net.sf.json.JSONArray;

import javax.naming.ldap.LdapContext;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:48 PM
 */
public class NCSAGroupHandler extends GroupHandler {
    public NCSAGroupHandler(LDAPClaimsSource claimsSource, String userName) {
        this.userName = userName;
        this.claimsSource = claimsSource;
    }

    LDAPClaimsSource claimsSource;

    String userName;
    /**
     * The form of an LDAP record is cn=group,buncha stuff.
     *
     * @param jsonArray
     * @return
     */
    @Override
    public Groups parse(JSONArray jsonArray) {
        try {
            return LDAPClaimsSource.get_NEW_Gid(claimsSource.getLDAPCfg(), userName);
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
        return new Groups();
    }

    LdapContext ctx;
}
