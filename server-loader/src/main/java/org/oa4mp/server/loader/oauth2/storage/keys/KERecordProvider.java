package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;

import javax.inject.Provider;
import java.security.SecureRandom;

public class KERecordProvider<V extends KERecord> extends IdentifiableProviderImpl<V> {
    public KERecordProvider(Provider<Identifier> idProvider) {
        super(idProvider);
    }

    SecureRandom sr = new SecureRandom();
    int byteCount = 12;
    @Override
    public V get(boolean createNewIdentifier) {
        return (V) new KERecord(newID());
    }

    /**
     * Create a new random identifier with a timestamp. Note that this <I>not</I>
     * the same as the JWK kid since we are managing them as independent entities.
     * @return
     */
    /*
        internal note -- could have done this with the OA2TokenForge machinery, but that
        is complete overkill for a simple identifier, and it's way messier.
        These are intended for internal use only and should never be seen by a user.
        Just mint it here.
     */
    protected Identifier newID(){
        return idProvider.get();
/*
        byte[] randomBytes = new byte[byteCount];
        sr.nextBytes(randomBytes);
        BigInteger bi = new BigInteger(randomBytes);
        return  "oa4mp:/jwks/id/" + bi.abs().toString(16).toLowerCase() + "/" + System.currentTimeMillis();
*/
    }
}
