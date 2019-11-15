package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

public class AdminClient extends BaseClient {
    /**
     *  The maximum number of OIDC (i.e. standard) clients an admin client may create before
     *  being refused by the system. This is to prevent error (e.g. an admin client is used in a
     *  script which is misbehaving). This may be increased and is simply the default for newly
     *  created admin clients.
     */
    public static int DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS = 50;
    public AdminClient(Identifier identifier) {
        super(identifier);
    }

    String virtualOrganization;
    String issuer;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getVirtualOrganization() {
        return virtualOrganization;
    }

    public void setVirtualOrganization(String virtualOrganization) {
        this.virtualOrganization = virtualOrganization;
    }
    int maxClients = DEFAULT_MAX_NUMBER_OF_OIDC_CLIENTS;

    /**
     * The maximum number of standard clients this admin client can create before the system
     * refuses to accept any more.
     * @return
     */
    public int getMaxClients() {
        return maxClients;
    }

    public void setMaxClients(int maxClients) {
        this.maxClients = maxClients;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AdminClient)) {
            return false;
        }
        AdminClient ac = (AdminClient) obj;
        if (!checkEquals(getIssuer(), ac.getIssuer())) return false;
        if (!checkEquals(getVirtualOrganization(), ac.getVirtualOrganization())) return false;
        if(getMaxClients() != ac.getMaxClients()) return false;
        return super.equals(obj);
    }

    @Override
    public BaseClient clone() {
        AdminClient ac = new AdminClient(getIdentifier());
        populateClone(ac);
        return ac;
    }

    @Override
    protected void populateClone(BaseClient client) {
        AdminClient c = (AdminClient) client;
        super.populateClone(c);
        c.setCreationTS(getCreationTS());
        c.setEmail(getEmail());
        c.setName(getName());
        c.setSecret(getSecret());
        c.setMaxClients(getMaxClients());
    }
}