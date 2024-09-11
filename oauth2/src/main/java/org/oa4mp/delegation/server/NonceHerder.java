package org.oa4mp.delegation.server;

import edu.uiuc.ncsa.security.core.util.StringUtils;
import org.oa4mp.delegation.server.server.InvalidNonceException;
import org.apache.commons.codec.binary.Base64;

import java.security.SecureRandom;
import java.util.HashSet;

/**
 * A class to manage nonces (with an in-memory store) and create new ones.
 * <p>Created by Jeff Gaynor<br>
 * on 9/24/13 at  1:18 PM
 */
public class NonceHerder {
    static HashSet<String> nonces = null;

    public static HashSet<String> getNonces() {
        if (nonces == null) {
            nonces = new HashSet<String>();
        }
        return nonces;
    }

    public static void removeNonce(String nonce){
                    getNonces().remove(nonce);
    }

    /**
     * Checks if this herder knows about this nonce. It returns a boolean. To test for nonces, use
     * {@link #checkNonce(String)}
     * @param nonce
     * @return
     */
    public static boolean hasNonce(String nonce) {
        return getNonces().contains(nonce);
    }

    /**
     * Checks if a non-trivial nonce is here and if so, throws an exception. If not,
     * the new nonce is added.
     * @param nonce
     */
    public static void checkNonce(String nonce) {
        if(StringUtils.isTrivial(nonce)){
            return; // not a lot we can do if they don't give us a nonce.
        }
        if (hasNonce(nonce)) {
            throw new InvalidNonceException(" nonce used");
        }
        putNonce(nonce);
    }

    static SecureRandom random = new SecureRandom();

    public static void putNonce(String nonce){
        getNonces().add(nonce);
    }

    /**
     * Creates a default nonce that is 32 bytes long.
     * @return
     */
    public static String createNonce() {
        return createNonce(32);
    }
    public static String createNonce(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        String nonce =  Base64.encodeBase64URLSafeString(bytes);
        putNonce(nonce);
        return nonce;
    }

}
