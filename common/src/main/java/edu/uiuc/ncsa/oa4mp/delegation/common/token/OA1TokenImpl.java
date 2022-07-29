package edu.uiuc.ncsa.oa4mp.delegation.common.token;

import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.OA1Token;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.TokenImpl;
import net.sf.json.JSONObject;

import java.net.URI;

import static edu.uiuc.ncsa.security.core.util.BeanUtils.checkNoNulls;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/9/20 at  9:00 AM
 */
public class OA1TokenImpl extends TokenImpl implements OA1Token {
    public OA1TokenImpl(URI token, URI sharedSecret) {
        super(token);
        this.sharedSecret = sharedSecret;
    }

   /*
   Note that this does not have a single argument (string) constructor because the shared secret would be lost
   in non-JSON cases.
    */
    URI sharedSecret;

    public void setSharedSecret(URI sharedSecret) {
        this.sharedSecret = sharedSecret;
    }


    public URI getURISharedSecret() {
        return sharedSecret;
    }

    public String getSharedSecret() {
        if (sharedSecret == null) return null;
        return getURISharedSecret().toString();
    }

    public void setSharedSecret(String sharedSecret) {
        if (sharedSecret == null) {
            this.sharedSecret = null;
        } else {
            setSharedSecret(URI.create(sharedSecret));
        }
    }

    @Override
    protected StringBuilder createString() {
        StringBuilder sb = super.createString();
        if (getSharedSecret() != null) {
            sb.append(", secret=" + getSharedSecret());
        }
        return sb;
    }

    @Override
    public boolean equals(Object obj) {
        // special case: If the object is null and the values are, then accept them as being equal.
        if (!(obj instanceof OA1TokenImpl)) {
            return false;
        }
        OA1TokenImpl at = (OA1TokenImpl) obj;
        if (obj == null && getURIToken() == null && getSharedSecret() == null) return true;
        if (!checkNoNulls(getSharedSecret(), at.getSharedSecret())) return false;
        return super.equals(obj);
    }


    @Override
    public JSONObject toJSON() {
        JSONObject json = super.toJSON();
        if(sharedSecret != null) {
            json.put(SHARED_SECRET_KEY, sharedSecret.toString());
        }
        return json;
    }

    @Override
    public void fromJSON(JSONObject json) {
        super.fromJSON(json);
        if(json.containsKey(SHARED_SECRET_KEY)){
            this.sharedSecret = URI.create(json.getString(SHARED_SECRET_KEY));
        }
    }
}
