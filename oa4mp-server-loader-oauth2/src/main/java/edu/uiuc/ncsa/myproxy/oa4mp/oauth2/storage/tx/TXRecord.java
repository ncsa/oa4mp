package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public class TXRecord extends IdentifiableImpl {
    public TXRecord(Identifier identifier) {
        super(identifier);
    }


    public Identifier getParentID() {
        return parentID;
    }

    public void setParentID(Identifier parentID) {
        this.parentID = parentID;
    }

    public long getLifetime() {
        return lifetime;
    }

    public void setLifetime(long lifetime) {
        this.lifetime = lifetime;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    String tokenType;
    /**
     * Convenience method. Just got tired of translating this
     * @param newScopes
     */
    public void setScopes(Collection<String> newScopes) {
        scopes = new ArrayList<>();
        scopes.addAll(newScopes);
    }

    public void setScopes(List<String> scopes) {
        this.scopes = scopes;
    }

    public boolean hasAudience() {
        return audience != null && !audience.isEmpty();
    }

    public List<String> getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<URI> getResource() {
        return resource;
    }

    public void setResource(List<URI> resource) {
        this.resource = resource;
    }

    public boolean hasResources() {
        return resource != null && !resource.isEmpty();
    }

    public boolean hasScopes() {
        return scopes != null && !scopes.isEmpty();
    }

    List<String> audience;
    long expiresAt = System.currentTimeMillis();
    long lifetime = 0L;
    long issuedAt = System.currentTimeMillis();
    String issuer;
    Identifier parentID;
    List<String> scopes;
    List<URI> resource;
    boolean valid;
}
