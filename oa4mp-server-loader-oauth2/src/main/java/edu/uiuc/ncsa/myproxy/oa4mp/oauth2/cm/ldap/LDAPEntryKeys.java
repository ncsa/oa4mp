package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:31 PM
 */
public class LDAPEntryKeys extends SerializationKeys {
    public LDAPEntryKeys() {
        identifier("id");
    }

    protected String ldap = "ldap";
    public String ldap(String... x){
        if (0 < x.length) ldap = x[0];
            return ldap;
    }

    protected String clientID = "client_id";
    public String clientID(String... x){
         if (0 < x.length) clientID= x[0];
             return clientID;
     }

    @Override
    public List<String> allKeys() {
        List<String> allKeys =  super.allKeys();
        allKeys.add(ldap());
        allKeys.add(clientID());
        return allKeys;

    }
}
