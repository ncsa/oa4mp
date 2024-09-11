package org.oa4mp.server.admin.myproxy.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/24 at  11:49 AM
 */
public class MEProvider<V extends MigrationEntry> implements IdentifiableProvider<V> {
    SecureRandom secureRandom = new SecureRandom();

    @Override
    public V get(boolean createNewIdentifier) {
        return get();
    }

    @Override
    public V get() {
        byte[] b = new byte[16];
        secureRandom.nextBytes(b);
        BigInteger bigInteger = new BigInteger(b);
        String rawID = bigInteger.abs().toString(16).toLowerCase();
        return (V) new MigrationEntry(BasicIdentifier.newID(rawID));
    }
}
