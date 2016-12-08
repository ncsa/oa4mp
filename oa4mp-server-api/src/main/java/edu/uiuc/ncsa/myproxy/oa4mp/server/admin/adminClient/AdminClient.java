package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

public class AdminClient extends BaseClient {
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

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof AdminClient)) {
            return false;
        }
        AdminClient ac = (AdminClient) obj;
        if (!checkEquals(getIssuer(), ac.getIssuer())) return false;
        if (!checkEquals(getVirtualOrganization(), ac.getVirtualOrganization())) return false;

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
    }
}