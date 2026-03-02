package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

import javax.inject.Provider;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Create a new random identifier with a timestamp. Note that this <I>not</I>
 * the same as the JWK kid since we are managing them as independent entities.
 */

public class KEIdentifierProvider implements Provider<Identifier> {
    @Override
    public Identifier get() {
        return newID();
    }
    SecureRandom sr = new SecureRandom();
    int byteCount = 8;

    /*
        internal note -- could have done this with the OA2TokenForge machinery, but that
        is complete overkill for a simple identifier, and it's way messier.
        These are intended for internal use only and should never be seen by a user.
        Just mint it here.
     */
    protected Identifier newID(){
        byte[] randomBytes = new byte[byteCount];
        sr.nextBytes(randomBytes);
        BigInteger bi = new BigInteger(randomBytes);
        String out= "oa4mp:/jwks/id/" + bi.abs().toString(16).toLowerCase() + "/" + System.currentTimeMillis();
       return BasicIdentifier.newID(out);
    }
}
