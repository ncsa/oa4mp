package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.ldap;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfiguration;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:27 PM
 */
public class LDAPEntry extends IdentifiableImpl {
    public LDAPEntry(Identifier identifier) {
        super(identifier);
    }
    public LDAPConfiguration getConfiguration() {
        return configuration;
    }

    protected LDAPConfiguration configuration;

    public void setConfiguration(LDAPConfiguration configuration) {
        this.configuration = configuration;
    }

    public Identifier getClientID() {
        return clientID;
    }

    public void setClientID(Identifier clientID) {
        this.clientID = clientID;
    }

    protected Identifier clientID;
}
