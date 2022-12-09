package edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidAlgorithmException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidSignatureException;
import edu.uiuc.ncsa.security.core.exceptions.UnsupportedJWTTypeException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.JWTUtil;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC9068Constants;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.MyKeyUtil;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URI;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * Creates JWT tokens. This will create both signed and unsigned tokens
 * if requested. The format is to have a header that describes the
 * content, including algorithm (fixed at "none" here) and a payload of claims. Both of these
 * are in JSON. The token then consists of based64 encoding both of these and <br><br>
 * encoded header + "."   + encoded payload + "." + signature<br><br>
 * If the token is unsigned, the last period is still manadatory and must end this.
 *
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/15 at  10:45 AM
 */

// Fixes OAUTH-164, adding id_token support.
public class JWTUtil2 {
    public static String TYPE = "typ";
    public static String KEY_ID = "kid";
    public static String ALGORITHM = "alg";
    public static String DEFAULT_TYPE = "JWT";

    /**
     * Creates an unsigned token.
     *
     * @param payload
     * @return
     */
    public static String createJWT(JSONObject payload) {
        return createJWT(payload, DEFAULT_TYPE);

    }
    public static String createJWT(JSONObject payload, String type) {
        JSONObject header = new JSONObject();
        header.put(TYPE, type);
        header.put(ALGORITHM, NONE_JWT);
        return concat(header, payload) + "."; // as per spec.
    }

    public static String createJWT(JSONObject payload, JSONWebKey jsonWebKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException, IOException {
         return createJWT(payload, jsonWebKey, DEFAULT_TYPE);
    }

    public static String createJWT(JSONObject payload, JSONWebKey jsonWebKey,String type) throws NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, InvalidKeyException, IOException {
        JSONObject header = new JSONObject();
        header.put(TYPE, type);
        header.put(KEY_ID, jsonWebKey.id);
        String signature = null;

        header.put(ALGORITHM, jsonWebKey.algorithm);

        if (jsonWebKey.algorithm.equals(NONE_JWT)) {
            signature = ""; // as per spec

        } else {
       //     DebugUtil.trace(JWTUtil.class, "Signing ID token with algorithm=" + jsonWebKey.algorithm);
            signature = sign(header, payload, jsonWebKey);
        }
        String x = concat(header, payload);
        return x + "." + signature;

    }


    protected static String concat(JSONObject header, JSONObject payload) {
        return Base64.encodeBase64URLSafeString(header.toString().getBytes()) + "." +
                Base64.encodeBase64URLSafeString(payload.toString().getBytes());
    }

    public static final String NONE_JWT = "none";
    public static final int NONE_KEY = 100;


    public static final String RS256_JWT = "RS256";
    public static final String RS256_JAVA = "SHA256withRSA";
    public static final int RS256_KEY = 101;

    public static final String RS384_JWT = "RS384";
    public static final String RS384_JAVA = "SHA384withRSA";
    public static final int RS384_KEY = 102;

    public static final String RS512_JWT = "RS512";
    public static final String RS512_JAVA = "SHA512withRSA";
    public static final int RS512_KEY = 103;

    protected static String sign(JSONObject header,
                                 JSONObject payload,
                                 JSONWebKey webkey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        return sign(concat(header, payload), webkey);
    }

    /*
     To do -- implement the support for elliptic curves signatures:
     SHA256withECDSA
     SHA384withECDSA
     SHA512withECDSA

     The default is RSA so we need a way to disambigute which is wanted.
     */
    protected static String sign(String x, JSONWebKey webkey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException {
         /*
         JWT alg name             Java name
                                  MD2withRSA
                                  MD5withRSA
         RS256                    SHA256withRSA
         RS348                    SHA384withRSA
         RS512                    SHA512withRSA
          */

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(webkey.privateKey.getEncoded());
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance(getJavaSignatureName(webkey.algorithm));
        signature.initSign(privateKey);
        byte[] content = x.getBytes();
        signature.update(content);
        byte[] signatureBytes = signature.sign();
        return Base64.encodeBase64URLSafeString(signatureBytes);

    }

    protected static String getJavaSignatureName(String algorithm) {
        if (algorithm.equals(NONE_JWT)) {
            return NONE_JWT;
        }
        if (algorithm.equals(RS256_JWT)) {
            return RS256_JAVA;
        }
        if (algorithm.equals(RS384_JWT)) {
            return RS384_JAVA;
        }
        if (algorithm.equals(RS512_JWT)) {
            return RS512_JAVA;
        }
        throw new IllegalArgumentException("Error: unknow algorithm \"" + algorithm + "\"");

    }

    public static boolean verify(JSONObject header, JSONObject payload, String sig, JSONWebKey webKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException {

        Object alg = header.get(ALGORITHM);
        if (alg == null || !(alg instanceof String)) {
            throw new IllegalStateException("Unknown algorithm");
        }
        String algorithm = (String) alg;
      //  DebugUtil.trace(JWTUtil.class, "Verifying JWT with algorithm =" + algorithm);
        Signature signature = null;
        if (algorithm.equals(NONE_JWT)) {
            if (!isTrivial(sig)) {
                throw new IllegalStateException("Error: the algorithm is " + NONE_JWT + " but there is  signature. ");
            }
            return true;
        }
        signature = Signature.getInstance(getJavaSignatureName(algorithm));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(webKey.publicKey.getEncoded());
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

        signature.initVerify(pubKey);
        signature.update(concat(header, payload).getBytes());
        boolean rc = signature.verify(Base64.decodeBase64(sig));
     //   DebugUtil.trace(JWTUtil.class, "Verification ok?" + rc);
        return rc;
    }

    /**
     * This returns header, payload and signature as the three elements of an array.
     * @param idToken
     * @return
     * @throws IllegalArgumentException if this is not parsable as a token of the form A.B[.C]
     */
    public static String[] decat(String idToken) {
        StringTokenizer st = new StringTokenizer(idToken, ".");
        // make sure these end up in tjhe right places
        String[] output = new String[3];

        switch (st.countTokens()) {
            case 0:
            case 1:
                throw new IllegalArgumentException("Error: No JWT components found.");
            case 2:
                output[HEADER_INDEX] = st.nextToken();
                output[PAYLOAD_INDEX] = st.nextToken();
                output[SIGNATURE_INDEX] = "";
                break;

                // At this point we do not allow for extra fields
            case 3:
                output[HEADER_INDEX] = st.nextToken();
                output[PAYLOAD_INDEX] = st.nextToken();
                output[SIGNATURE_INDEX] = st.nextToken();
                break;
            default:
                throw new IllegalArgumentException("Error: Too many JWT components.");
        }
        return output;
    }

    public static final int HEADER_INDEX = 0;
    public static final int PAYLOAD_INDEX = 1;
    public static final int SIGNATURE_INDEX = 2;

    /**
     * This will only peel off the header and payload. No verification of any sort is done!!
     *
     *
     * @param jwt
     * @return
     * @throws IllegalArgumentException if this is not JWT or the argument is null
     */
    public static JSONObject[] readJWT(String jwt) {
        String[] x = decat(jwt);
        JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[HEADER_INDEX])));
        JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[PAYLOAD_INDEX])));
        JSONObject rc[] = new JSONObject[2];
        rc[HEADER_INDEX] = h;
        rc[PAYLOAD_INDEX] = p;
        return rc;
    }

    /**
     * Verify and read a JWT. Note that this returns any of several exceptions which you should
     * check for as needed. An {@link IllegalArgumentException} means that this is not in fact
     * a JWT, all other exceptions relate to whether the internal structure passes muster.
     * @param jwt
     * @param webKeys
     * @return
     * @throws IllegalArgumentException if this is not a JWT or the argument is null
     * @throws InvalidAlgorithmException if there is no algorithm or the algorith is not supported
     * @throws InvalidSignatureException if the signature fails to verify
     * @throws UnsupportedJWTTypeException if the internal type of the token is not supported
     */
    public static JSONObject verifyAndReadJWT(String jwt, JSONWebKeys webKeys) {
        String[] x = decat(jwt);
        JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[HEADER_INDEX])));
        JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[PAYLOAD_INDEX])));
    //    DebugUtil.trace(JWTUtil.class, "header=" + h);
   //     DebugUtil.trace(JWTUtil.class, "payload=" + p);
        if (h.get(ALGORITHM) == null) {
            throw new InvalidAlgorithmException("Error: no algorithm.");
        } else {
            if (h.get(ALGORITHM).equals(NONE_JWT)) {
                DebugUtil.trace(JWTUtil.class, "unsigned id token. Returning payload");

                return p;
            }
        }
        if (!(h.get(TYPE).equals(DEFAULT_TYPE)||h.get(TYPE).equals(RFC9068Constants.HEADER_TYPE))) throw new UnsupportedJWTTypeException("Unsupported token type.");
        Object keyID = h.get(KEY_ID);
      //  DebugUtil.trace(JWTUtil.class, "key_id=" + keyID);

        if (keyID == null || !(keyID instanceof String)) {
            throw new InvalidAlgorithmException("Error: Unknown algorithm");
        }
        boolean isOK = false;
        try {
            JSONWebKey wk =  webKeys.get(h.getString(KEY_ID));
            if(wk == null){
                throw new IllegalArgumentException("Web key with id " + KEY_ID + " not found. Allows keys are " + webKeys.keySet());
            }
            if(wk.publicKey == null){
                throw new IllegalStateException("Web key with id " +  KEY_ID + " does not have a public key");
            }
            isOK = verify(h, p, x[SIGNATURE_INDEX], wk);
        } catch (Throwable t) {
            throw new InvalidSignatureException("Error: could not verify signature", t);
        }
        if (!isOK) {
            throw new InvalidSignatureException("Error: could not verify signature");
        }
        return p;
    }


    /**
     * Create a basic {@link ServiceClient} to get the keys from the well known page. If you require a special
     * setup (e.g. your own SSL certs), you will need to create your own ServiceClient and supply that in the
     * related call getJSONWebKeys(ServiceClient, String wellKnown).
     *
     * @param wellKnown
     * @return
     */
    public static JSONWebKeys getJsonWebKeys(String wellKnown) {
        if (wellKnown == null || wellKnown.isEmpty()) {
            throw new GeneralException("Error: missing well known URI. Cannot get keys");
        }
        ServiceClient serviceClient = new ServiceClient(URI.create(wellKnown));
        return getJsonWebKeys(serviceClient, wellKnown);
    }

    public static JSONWebKeys getJsonWebKeys(URI wellKnown) {
        if (wellKnown == null) {
            throw new GeneralException("Error: Missing well known uri. Cannot resolve the keys");
        }

        return getJsonWebKeys(wellKnown.toString());
    }

    public static JSONObject verifyAndReadJWT(String jwt, URI wellKnown) {
        if (wellKnown == null) {
            throw new GeneralException("Error: Missing well known uri. Cannot resolve the keys");
        }
        if (jwt == null || jwt.isEmpty()) {
            throw new GeneralException("Error: Missing or empty token.");
        }
        return verifyAndReadJWT(jwt, JWTUtil.getJsonWebKeys(wellKnown.toString()));
    }

    public static JSONWebKeys getJsonWebKeys(ServiceClient serviceClient, String wellKnown) {
        if (serviceClient == null) {
            throw new GeneralException("Error: Missing service client.");
        }
        if (wellKnown == null || wellKnown.isEmpty()) {
            throw new GeneralException("Error: missing well known URI. Cannot get keys");
        }

        // Fix for OAUTH-164, id_token support follows.
        String rawResponse = serviceClient.doGet(wellKnown);
        JSON rawJSON = JSONSerializer.toJSON(rawResponse);

        if (!(rawJSON instanceof JSONObject)) {
            throw new IllegalStateException("Error: Attempted to get JSON Object but returned result is not JSON");
        }
        JSONObject json = (JSONObject) rawJSON;
        String rawKeys = serviceClient.doGet(json.getString("jwks_uri"));
        JSONWebKeys keys = null;
        JSONObject claims = null;
        try {
            keys = JSONWebKeyUtil.fromJSON(rawKeys);
        } catch (Throwable e) {
            throw new GeneralException("Error getting keys", e);
        }
        return keys;
    }

    /**
     * Strictly for testing.
     * This will take two arguments, a file name containing the keys, the word decode|encode and a string.
     * If the word decode is used, then the string is decoded against the
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
        //    firstTest();
            //   firstTestB();
            //    otherTest();
         //   testSigning();
            JSONWebKeys keys = getJsonWebKeys("https://test.cilogon.org/oauth2/.well-known");
            //JSONWebKeys keys = getJsonWebKeys("https://lw-issuer.osgdev.chtc.io/scitokens-server/certs");
            System.out.println("Detected " + keys.size() + " keys on test.cilogon.org");
            //  testSigningDirectly();
            //testJWT_IO();
            // printKeys();
            // generateAndSign();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    public static void otherTest() throws Exception {
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File("/home/ncsa/dev/csd/config/keys.jwk"));
        JSONObject claims = verifyAndReadJWT(ID_TOKKEN, keys);
        System.out.println("claims=" + claims);

    }

    public static void testSigning() throws Exception {
        String h = "{\"typ\":\"JWT\",\"kid\":\"9k0HPG3moXENne\",\"alg\":\"RS256\"}";
        String p = "{\"iss\":\"https://ashigaru.ncsa.uiuc.edu:9443\",\"sub\":\"jgaynor\",\"exp\":1484764744,\"aud\":\"myproxy:oa4mp,2012:/client_id/14649e2f468450dac0c1834811dbd4c7\",\"iat\":1484763844,\"nonce\":\"0ZIi-EuxeC_X8AgB3VifOoqKiXWsz_NlXSzIu7h8rzU\",\"auth_time\":\"1484763843\"}\n";
        JSONObject header = JSONObject.fromObject(h);
        System.out.println("header=" + header);
        JSONObject payload = JSONObject.fromObject(p);
        System.out.println("payload=" + payload);
        System.out.println("base 64=" + concat(header, payload));
        //String keyID = "9k0HPG3moXENne";
        String keyID = "244B235F6B28E34108D101EAC7362C4E";
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File("/home/ncsa/dev/csd/config/polo-keys.jwk"));

        String idTokken = createJWT(payload, keys.get(keyID));
        System.out.println(idTokken);
        JSONObject claims = verifyAndReadJWT(idTokken, keys);
        System.out.println("claims = " + claims);
        JSONWebKey webKey = keys.get(keyID);
        System.out.println(MyKeyUtil.toX509PEM(webKey.publicKey));
    }

    public static void firstTest() throws Exception {
        PublicKey publicKey = MyKeyUtil.fromX509PEM(new FileReader("/tmp/pub.pem"));
                System.out.println(publicKey);

        JSONObject header = new JSONObject();
        header.put(TYPE, "JWT");
        header.put(ALGORITHM, "RS256");
        KeyPair keyPair = MyKeyUtil.generateKeyPair();
        JSONWebKey webKey = new JSONWebKey();
        webKey.algorithm = "RS256";
        webKey.privateKey = keyPair.getPrivate();
        //webKey.publicKey = keyPair.getPublic();
        webKey.publicKey = publicKey;
        webKey.id = "qwert";
        //webKey.type = "sig";
        System.out.println(JSONWebKeyUtil.toJSON(webKey));
        JSONObject payload = new JSONObject();
        payload.put("name", "jeff");
        payload.put("id", "sukjfhusdfsdjkfh");
        payload.put("other_claim", "skjdf93489ghiovs 98sd89wehi ws");
        payload.put("another_claim", "l;kfg8934789dfio9v 92w89 98wer");
        String tokken = createJWT(payload, webKey);

        System.out.println("JWT=" + tokken);
        JSONWebKeys keys = new JSONWebKeys(null);
        keys.put(webKey.id, webKey);
        System.out.println("claims=" + verifyAndReadJWT(tokken, keys));
        System.out.println("-----");
        // note that if the this last call
        // works it is because the verification works too.
    }

    public static void signAndVerify(JSONWebKeys keys, String keyID) throws Exception {
        String h = "{" +
                "  \"typ\": \"JWT\"," +
                "  \"kid\": \"9k0HPG3moXENne\"," +
                "  \"alg\": \"RS256\"" +
                "}";

        String p = "{\n" +
                "  \"iss\": \"https://ashigaru.ncsa.uiuc.edu:9443\"," +
                "  \"sub\": \"jgaynor\"," +
                "  \"exp\": 1484764744," +
                "  \"aud\": \"myproxy:oa4mp,2012:/client_id/14649e2f468450dac0c1834811dbd4c7\"," +
                "  \"iat\": 1484763844," +
                "  \"nonce\": \"0ZIi-EuxeC_X8AgB3VifOoqKiXWsz_NlXSzIu7h8rzU\"," +
                "  \"auth_time\": \"1484763843\"" +
                "}";
        JSONObject header = JSONObject.fromObject(h);
        JSONObject payload = JSONObject.fromObject(p);
        JSONWebKey key = keys.get(keyID);
        String signature = sign(header, payload, key);
        System.out.println(concat(header, payload) + "." + signature);
        System.out.println(MyKeyUtil.toX509PEM(key.publicKey));

        System.out.println("verified?" + verify(header, payload, signature, key));

    }

    public static void generateAndSign() throws Exception {
        String keyID = "aQEiCy2fJcVgkOft";
        KeyPair keyPair = MyKeyUtil.generateKeyPair();

        JSONWebKeys keys = new JSONWebKeys(keyID);
        JSONWebKey key = new JSONWebKey();
        key.privateKey = keyPair.getPrivate();
        key.publicKey = keyPair.getPublic();
        key.algorithm = RS256_JWT;
        key.id = keyID;
        key.use = "sig";
        key.type = "RSA";
        keys.put(key);
        System.out.println("Generating keys and signing.");
        signAndVerify(keys, keyID);

        JSONObject jsonKeys = JSONWebKeyUtil.toJSON(keys);
        JSONWebKeys keys2 = JSONWebKeyUtil.fromJSON(jsonKeys.toString(2));

        JSONWebKey webKey = keys2.get(keyID);
        System.out.println("Serializing, deserializing then signing.");

        signAndVerify(keys2, keyID);

    }


    public static void printKeys() throws Exception {
        String text = "eyJ0eXAiOiJKV1QiLCJraWQiOiI5azBIUEczbW9YRU5uZSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FzaGlnYXJ1Lm5jc2EudWl1Yy5lZHU6OTQ0MyIsInN1YiI6ImpnYXlub3IiLCJleHAiOjE0ODQ3NjQ3NDQsImF1ZCI6Im15cHJveHk6b2E0bXAsMjAxMjovY2xpZW50X2lkLzE0NjQ5ZTJmNDY4NDUwZGFjMGMxODM0ODExZGJkNGM3IiwiaWF0IjoxNDg0NzYzODQ0LCJub25jZSI6IjBaSWktRXV4ZUNfWDhBZ0IzVmlmT29xS2lYV3N6X05sWFN6SXU3aDhyelUiLCJhdXRoX3RpbWUiOiIxNDg0NzYzODQzIn0";
        String keyID = "aQEiCy2fJcVgkOft";
        KeyPair keyPair = MyKeyUtil.generateKeyPair();

        JSONWebKeys keys = new JSONWebKeys(keyID);
        JSONWebKey key = new JSONWebKey();
        key.privateKey = keyPair.getPrivate();
        key.publicKey = keyPair.getPublic();
        key.algorithm = "RS256";
        key.id = keyID;
        key.use = "sig";
        key.type = "RSA";
        keys.put(key);

        System.out.println("----- START keys");
        System.out.println(MyKeyUtil.toX509PEM(keyPair.getPublic()));
        System.out.println(MyKeyUtil.toPKCS1PEM(keyPair.getPrivate()));
        System.out.println(MyKeyUtil.toPKCS8PEM(keyPair.getPrivate()));
        System.out.println("----- END keys\n");


        JSONObject jsonKeys = JSONWebKeyUtil.toJSON(keys);
        JSONWebKeys keys2 = JSONWebKeyUtil.fromJSON(jsonKeys.toString(2));

        JSONWebKey webKey = keys2.get(keyID);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(webKey.privateKey.getEncoded());
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        System.out.println(MyKeyUtil.toX509PEM(webKey.publicKey));
        System.out.println(MyKeyUtil.toPKCS1PEM(privateKey));
        System.out.println(MyKeyUtil.toPKCS8PEM(privateKey));

    }

    public static void firstTestB() throws Exception {
        String keyID = "9k0HPG3moXENne";
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File("/home/ncsa/dev/csd/config/keys.jwk"));

        JSONObject payload = new JSONObject();
        payload.put("name", "jeff");
        payload.put("id", "sukjfhusdfsdjkfh");
        payload.put("other_claim", "skjdf93489ghiovs 98sd89wehi ws");
        payload.put("another_claim", "l;kfg8934789dfio9v 92w89 98wer");
        JSONWebKey webKey = keys.get(keyID);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(webKey.privateKey.getEncoded());
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        System.out.println(MyKeyUtil.toX509PEM(webKey.publicKey));
        System.out.println(MyKeyUtil.toPKCS1PEM(privateKey));
        System.out.println(MyKeyUtil.toPKCS8PEM(privateKey));
        String tokken = createJWT(payload, keys.get(keyID));

        System.out.println("JWT=" + tokken);
        System.out.println("claims=" + verifyAndReadJWT(tokken, keys));
        System.out.println("-----");

        // note that if the this last call
        // works it is because the verification works too.
    }

    public static void testSigningDirectly() throws Exception {
        String keyID = "9k0HPG3moXENne";
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File("/home/ncsa/dev/csd/config/keys.jwk"));

        JSONWebKey jsonWebKey = keys.get(keyID);

        JSONObject payload = new JSONObject();
        payload.put("name", "jeff");
        payload.put("id", "sukjfhusdfsdjkfh");
        payload.put("other_claim", "skjdf93489ghiovs 98sd89wehi ws");
        payload.put("another_claim", "l;kfg8934789dfio9v 92w89 98wer");
        JSONObject header = new JSONObject();
        header.put(TYPE, "JWT");
        header.put(KEY_ID, jsonWebKey.id);

        header.put(ALGORITHM, jsonWebKey.algorithm);

        // create signature
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(jsonWebKey.privateKey.getEncoded());
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        Signature signature = Signature.getInstance(getJavaSignatureName(jsonWebKey.algorithm));
        Signature signature1 = Signature.getInstance(getJavaSignatureName(jsonWebKey.algorithm));
        //         signature.initSign(jsonWebKey.privateKey);
        signature.initSign(privateKey);
        byte[] content = concat(header, payload).getBytes();
        signature.update(content);
        byte[] signatureBytes = signature.sign();

        JSONWebKeys pubKeys = JSONWebKeyUtil.makePublic(keys);
        JSONWebKey jsonWebKey1 = pubKeys.get(keyID);
        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(jsonWebKey1.publicKey.getEncoded());
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

        signature1.initVerify(pubKey);
        signature1.update(content);

        System.out.println("sig verifies?=" + signature1.verify(signatureBytes));

    }

    public static void testJWT_IO() throws Exception {
        String header = "{" +
                "  \"typ\": \"JWT\"," +
                "  \"kid\": \"9k0HPG3moXENne\"," +
                "  \"alg\": \"RS256\"" +
                "}";

        String payload = "{\n" +
                "  \"iss\": \"https://ashigaru.ncsa.uiuc.edu:9443\"," +
                "  \"sub\": \"jgaynor\"," +
                "  \"exp\": 1484764744," +
                "  \"aud\": \"myproxy:oa4mp,2012:/client_id/14649e2f468450dac0c1834811dbd4c7\"," +
                "  \"iat\": 1484763844," +
                "  \"nonce\": \"0ZIi-EuxeC_X8AgB3VifOoqKiXWsz_NlXSzIu7h8rzU\"," +
                "  \"auth_time\": \"1484763843\"" +
                "}";
        String keyID = "9k0HPG3moXENne";
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File("/home/ncsa/dev/csd/config/keys.jwk"));

        JSONWebKey jsonWebKey = keys.get(keyID);
        JSONObject h = JSONObject.fromObject(header);
        JSONObject p = JSONObject.fromObject(payload);
        String signature = sign(h, p, jsonWebKey);
        System.out.println(signature);

    }

    public static String ID_TOKKEN = "eyJ0eXAiOiJKV1QiLCJraWQiOiI5azBIUEczbW9YRU5uZSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FzaGlnYXJ1Lm5jc2EudWl1Yy5lZHU6OTQ0MyIsInN1YiI6ImpnYXlub3IiLCJleHAiOjE0ODQ3NjQ3NDQsImF1ZCI6Im15cHJveHk6b2E0bXAsMjAxMjovY2xpZW50X2lkLzE0NjQ5ZTJmNDY4NDUwZGFjMGMxODM0ODExZGJkNGM3IiwiaWF0IjoxNDg0NzYzODQ0LCJub25jZSI6IjBaSWktRXV4ZUNfWDhBZ0IzVmlmT29xS2lYV3N6X05sWFN6SXU3aDhyelUiLCJhdXRoX3RpbWUiOiIxNDg0NzYzODQzIn0.PXxUPRJ1aPQmcgfidz1xf28Ip3g3TCWldAPT25JVhsu5kJw75mDjPFVaHvcGOnxO121PAlisQlqARqpx3ytW720odRHEhv3JmVjvoRyKeCHzAP7va75cZmgOWDUI9SONDuNcuomRbUrRyLwrgH2CtBrKr05AowYojkJspRf3a5z6K5s-6ahbUlm7AAmYFDceNtQBeiutCZBfP4_gMLAxdQb7pHfyocKslAV0CwtAKYvqUpkIHuUYsc5CXYuan2Ox0If_pMJC4uV3Ov4banMNLwKeQPRUyWhHLnhrMl5KeoaEtL2nW4X7JIqK8EX-esmjQmr_NVI7DP8DV1C3OjHkpA";

}
