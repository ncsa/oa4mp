package org.oa4mp.delegation.server.server;

import org.apache.commons.codec.digest.DigestUtils;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/27/21 at  9:20 AM
 */

public class RFC7636Util {
    public static final String CODE_VERIFIER = "code_verifier";
    public static final String CODE_CHALLENGE = "code_challenge";
    public static final String CODE_CHALLENGE_METHOD = "code_challenge_method";

    public static final String METHOD_PLAIN = "plain";
    public static final String METHOD_S256 = "S256";

    public static String createChallenge(String verifier, String method) {
        switch (method) {
            case METHOD_S256:
                return encodeBase64URLSafeString(DigestUtils.sha256(verifier.getBytes(StandardCharsets.UTF_8)));
            case METHOD_PLAIN:
                return verifier;
        }
        throw new IllegalArgumentException("unknown method type");

    }


    static SecureRandom secureRandom = new SecureRandom();
    public static int byteCount = 48; //  = 384 bits

    public static String createVerifier() {
        byte[] ba = new byte[byteCount];
        secureRandom.nextBytes(ba);
        return encodeBase64URLSafeString(ba);
    }

    public static void main(String[] args) {
        String v = createVerifier();
        System.out.println("verifier: " + v);
        System.out.println("challenge: " + createChallenge(v, METHOD_S256));

        // Next bit is directly from the example in the spec to check this works.
        // If you get all oks below, then this is spec compliant.
        int[] rawInts = new int[]{116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
                187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
                132, 141, 121};
        byte[] testBytes = new byte[rawInts.length];
        for (int i = 0; i < rawInts.length; i++) {
            testBytes[i] = (byte) rawInts[i];
        }
        String testV = encodeBase64URLSafeString(testBytes);
        System.out.println("testV: " + testV);
        System.out.println("verifier ok? " + testV.equals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        // now we compute the code challenge
        String testCC = createChallenge(testV, METHOD_S256);
        System.out.println("testCC:" + testCC);
        System.out.println("challenge ok? " + testCC.equals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));

    }
}

