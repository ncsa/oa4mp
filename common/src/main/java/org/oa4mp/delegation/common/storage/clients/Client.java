package org.oa4mp.delegation.common.storage.clients;


import edu.uiuc.ncsa.security.core.Identifier;

import java.util.Collection;
import java.util.LinkedList;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * Models a client.
 * <p>Created by Jeff Gaynor<br>
 * on Mar 15, 2011 at  5:09:20 PM
 */


public class Client extends BaseClient {

    @Override
    public Client clone() {
        Client c = new Client(getIdentifier());
        populateClone(c);
        return c;
    }

    @Override
    protected void populateClone(BaseClient client) {
        Client c = (Client)client;
        super.populateClone(c);
        c.setErrorUri(getErrorUri());
        c.setHomeUri(getHomeUri());
        c.setProxyLimited(isProxyLimited());
        c.setServiceClient(isServiceClient());
    }

    public boolean isProxyLimited() {
        return proxyLimited;
    }

    public void setProxyLimited(boolean proxyLimited) {
        this.proxyLimited = proxyLimited;
    }

    boolean proxyLimited = false;

    public Client(Identifier identifier) {
        super(identifier);
    }

    public String getHomeUri() {
        return homeUri;
    }

    public void setHomeUri(String homeUri) {
        this.homeUri = homeUri;
    }

    String homeUri;

    String errorUri;

    public String getErrorUri() {
        return errorUri;
    }

    public void setErrorUri(String errorUri) {
        this.errorUri = errorUri;
    }

    @Override
    public boolean equals(Object obj) {
        if(!super.equals(obj)) return false;
        Client c = (Client) obj;
        if (!checkEquals(getHomeUri(), c.getHomeUri())) return false;
        if (!checkEquals(getErrorUri(), c.getErrorUri())) return false;
        if (isProxyLimited() != c.isProxyLimited()) return false;
        return true;
    }


    @Override
    public String toString() {
        return getClass().getSimpleName() + "[name=\"" + getName() +
                "\", id=\"" + getIdentifierString() +
                "\", homeUri=\"" + getHomeUri() +
                "\", errorUri=\"" + getErrorUri() +
                "\", email=\"" + getEmail() +
                "\", serviceClient=\"" + isServiceClient() +
                "\", secret=" + (getSecret()==null?"(none)":getSecret().substring(0,Math.min(25, getSecret().length()))) +
                "\", proxy limited=" + isProxyLimited() +
                "]";
    }
    public Collection<String> getScopes() {
        return scopes;
    }

    public void setScopes(Collection<String> scopes) {
        this.scopes = scopes;
    }

    Collection<String> scopes = new LinkedList<>();

}
