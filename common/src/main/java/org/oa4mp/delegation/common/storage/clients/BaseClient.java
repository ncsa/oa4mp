package org.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;

import java.net.URI;
import java.util.Date;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkEquals;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/12/16 at  4:32 PM
 */
public class BaseClient extends Monitored {

    public BaseClient(Identifier identifier) {
        super(identifier);
    }

    @Override
    public BaseClient clone() {
        BaseClient c = new BaseClient(getIdentifier());
        populateClone(c);
        return c;
    }

    protected void populateClone(BaseClient c) {
        c.setCreationTS(getCreationTS());
        c.setEmail(getEmail());
        c.setName(getName());
        c.setSecret(getSecret());
        c.setJWKS(getJWKS());
        c.setJwksURI(getJwksURI());
    }

    JSONWebKeys jwks;

    public URI getJwksURI() {
        return jwksURI;
    }

    public void setJwksURI(URI jwksURI) {
        this.jwksURI = jwksURI;
    }

    public boolean hasJWKSURI() {
        return jwksURI != null;
    }

    URI jwksURI;

    public JSONWebKeys getJWKS() {
        return jwks;
    }

    public void setJWKS(JSONWebKeys jwks) {
        this.jwks = jwks;
    }

    public boolean hasJWKS() {
        return jwks != null;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    String secret;

    String name;
    Date creationTS = new java.sql.Timestamp(new Date().getTime());
    String email;


    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Date getCreationTS() {

        return creationTS;
    }

    public void setCreationTS(Date creationTS) {
        this.creationTS = creationTS;
    }

    public Date getLastModifiedTS() {
        return lastModifiedTS;
    }

    public void setLastModifiedTS(Date lastModifiedTS) {
        this.lastModifiedTS = lastModifiedTS;
    }

    Date lastModifiedTS = new java.sql.Timestamp(new Date().getTime());


    @Override
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        BaseClient c = (BaseClient) obj;
        if (!checkEquals(getSecret(), c.getSecret())) return false;
        if (!checkEquals(getName(), c.getName())) return false;
        if (!checkEquals(getJwksURI(), c.getJwksURI())) return false;
        if (!checkEquals(getEmail(), c.getEmail())) return false;
        if (!DateUtils.equals(getCreationTS(), c.getCreationTS())) return false;
        return true;
    }


    @Override
    public String toString() {
        return getClass().getSimpleName() + "[name=\"" + getName() +
                "\", id=\"" + getIdentifierString() +
                "\", email=\"" + getEmail() +
                "\", jwks=\"" + (hasJWKS() ? getJWKS() : "(none)") +
                "\", jwksURI=\"" + (hasJWKS() ? getJwksURI() : "(none)") +
                "\", secret=" + (getSecret() == null ? "(none)" : getSecret().substring(0, 25)) +
                "]";
    }

    public boolean isDebugOn() {
        return debugOn;
    }

    public void setDebugOn(boolean debugOn) {
        this.debugOn = debugOn;
    }

    boolean debugOn = false;
}
