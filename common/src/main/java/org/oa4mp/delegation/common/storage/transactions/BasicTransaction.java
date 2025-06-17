package org.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.cache.Cacheable;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableImpl;
import org.oa4mp.delegation.common.token.*;

/**
 * A bean holding a transaction.
 * <p>Created by Jeff Gaynor<br>
 * on May 3, 2011 at  3:28:17 PM
 */
public class BasicTransaction extends IdentifiableImpl implements Cacheable {

    public BasicTransaction(Identifier identifier) {
        super(identifier);
    }

    public BasicTransaction(AuthorizationGrant ag) {
        super(BasicIdentifier.newID(ag.getToken()));
        setAuthorizationGrant(ag);
    }

    public boolean hasAccessToken() {
        return accessToken != null;
    }

    public boolean hasAuthorizationGrant() {
        return authorizationGrant != null;
    }

    public boolean hasProtectedAsset() {
        return protectedAsset != null;
    }

    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    public AuthorizationGrant getAuthorizationGrant() {
        return authorizationGrant;
    }

    public void setAuthorizationGrant(AuthorizationGrant authorizationGrant) {
        this.authorizationGrant = authorizationGrant;
        if(getIdentifier() == null) {
            // only reset the identifier if it is not already set.
            setIdentifier(BasicIdentifier.newID(authorizationGrant.getToken()));
        }
    }

   protected AuthorizationGrant authorizationGrant;
    AccessToken accessToken = null;
    ProtectedAsset protectedAsset;


    public ProtectedAsset getProtectedAsset() {
        return protectedAsset;
    }

    public void setProtectedAsset(ProtectedAsset protectedAsset) {
        this.protectedAsset = protectedAsset;
    }
    protected boolean checkTokenEquals(NewToken token1, NewToken token2){
        if(token1 == null){
            if(token2 == null) return true;
            return false;
        }else{
            if(token2 == null) return false;
            return token1.equals(token2);
        }

    }
    public boolean equals(Object obj) {
        if (!super.equals(obj)) return false;
        if (!(obj instanceof BasicTransaction)) return false;
        BasicTransaction t = (BasicTransaction) obj;

        if(!checkTokenEquals(getAuthorizationGrant(), t.getAuthorizationGrant())) return false;
        if(!checkTokenEquals(getAccessToken(), t.getAccessToken())) return false;
        return true;
    }


    public String toString() {
        String out = "Transaction[";
        out = out + "id=" + getIdentifierString() + ", auth grant=" + (hasAuthorizationGrant() ? getAuthorizationGrant() : "(none)");
        out = out + ", access token=" + (hasAccessToken() ? getAccessToken() : "(none)");
        return out + "]";
    }


}
