package org.oa4mp.delegation.common.token;

import edu.uiuc.ncsa.security.core.Identifier;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/9/20 at  8:34 AM
 */
public interface NewToken extends Token{
    boolean isExpired();
    String getVersion();
    long getLifetime();
    long getIssuedAt();
    JSONObject toJSON();
    void fromJSON(JSONObject json);
   // void fromString(String rawToken);
     void decodeToken(String rawb64String);
     String encodeToken();
    long OLD_SYSTEM_DEFAULT_LIFETIME = 1000L*60L*15L; // 15 minutes.
    URI getJti();
    Identifier getJTIAsIdentifier();
}
