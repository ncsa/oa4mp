package org.oa4mp.delegation.server.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.oa4mp.delegation.server.JWTUtil;
import org.oa4mp.delegation.server.server.RFC9068Constants;
import edu.uiuc.ncsa.security.core.exceptions.*;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.StringTokenizer;

/**
 * Creates JWT tokens from their serialized form H.P.S (Header, Payload and Signature),
 * signs them or verifies them. This will create both signed and unsigned tokens
 * if requested. The format is to have a header that describes the
 * content, including algorithm (fixed at "none" here) and a payload of claims. Both of these
 * are in JSON. The token then consists of based64 encoding both of these and <br><br>
 * encoded header + "."   + encoded payload + "." + signature<br><br>
 * If the token is unsigned, the last period is still manadatory and must end this.
 *
 * <p>Created by Jeff Gaynor<br>
 * on 2/9/15 at  10:45 AM
 */

// Fixes https://gateways.atlassian.net/browse/OAUTH-164, adding id_token support.
public class MyOtherJWTUtil2 {
    public static String TYPE = "typ";
    public static String KEY_ID = "kid";
    public static String ALGORITHM = "alg";
    public static String DEFAULT_TYPE = "JWT";

    public JWKUtil2 getJwkUtil2() {
        if (jwkUtil2 == null) {
            jwkUtil2 = new JWKUtil2();
        }
        return jwkUtil2;
    }

    public void setJwkUtil2(JWKUtil2 jwkUtil2) {
        this.jwkUtil2 = jwkUtil2;
    }

    JWKUtil2 jwkUtil2;

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

    public static String createJWT(JSONObject payload, JSONWebKey jsonWebKey) throws ParseException, JOSEException {
        return createJWT(payload, jsonWebKey, DEFAULT_TYPE);
    }

    public static String createJWT(JSONObject payload, JSONWebKey jsonWebKey, String type) throws ParseException, JOSEException {
        JSONObject header = new JSONObject();
        header.put(TYPE, type);
        // Don't send an empty kid. Every key should have one though, but a missing one is not an error.
        if (jsonWebKey.id != null && jsonWebKey.id.length() != 0) {
            header.put(KEY_ID, jsonWebKey.id);
        }
        String token = null;

        header.put(ALGORITHM, jsonWebKey.algorithm);

        if (jsonWebKey.algorithm.equals(NONE_JWT)) {
            token = concat(header, payload) +"."; // as per spec. Ends with a period if not signed.

        } else {
            token = sign(header, payload, jsonWebKey);
        }
        return token;
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

    /*
        protected static String sign(JSONObject header,
                                     JSONObject payload,
                                     JSONWebKey webkey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

            return sign(concat(header, payload), webkey);
        }
    */


    protected static String sign(JSONObject header,
                                 JSONObject payload,
                                 JSONWebKey webkey) throws JOSEException, ParseException {
        JWSAlgorithm jwsAlgorithm = new JWSAlgorithm(header.getString(ALGORITHM));
        JWSHeader jwsHeader = JWSHeader.parse(header);



                /* for some reason, the builder is not compiling right in the IDE.
                .Builder(Algorithm.parse(header.getString(ALGORITHM)))
                .type(JOSEObjectType.JWT)
                .build();*/
        JWTClaimsSet jwsPayload = JWTClaimsSet.parse(payload);
        SignedJWT signedJWT = new SignedJWT(jwsHeader, jwsPayload);
        JWSSigner signer = null;
        boolean unsupportedSigner = true;
        if (webkey.isRSAKey()) {
            signer = new RSASSASigner(webkey.privateKey);
            unsupportedSigner = false;
        }
        if (webkey.isECKey()) {
            signer = new ECDSASigner((ECPrivateKey) webkey.privateKey);
            unsupportedSigner = false;
        }
        if (unsupportedSigner) {
            throw new UnsupportedProtocolException("unsupported key type for signature verification");
        }
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    /*
val header = JWSHeader.Builder(JWSAlgorithm.ES256K)
    .type(JOSEObjectType.JWT)
    .keyID(key.keyID)
    .build();
val payload = JWTClaimsSet.Builder()
    .issuer("me")
    .audience("you")
    .subject("bob")
    .expirationTime(Date.from(Instant.now().plusSeconds(120)))
    .build()

val signedJWT = SignedJWT(header, payload)
signedJWT.sign(ECDSASigner(key.toECPrivateKey()))
val jwt: String = signedJWT.serialize()     */

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
        throw new IllegalArgumentException("unknown algorithm \"" + algorithm + "\"");

    }

    public static boolean verify(Base64URL header, Base64URL payload, Base64URL signature, JSONWebKey webKey) throws ParseException, JOSEException {
        if (signature == null) {
            // odd ball case of unsigned JWT. This must be checked
            JSONObject json = JSONObject.fromObject(header.decodeToString());
            Object alg = json.get(ALGORITHM);
            if (alg == null || !(alg instanceof String)) {
                throw new IllegalStateException("Unknown algorithm");
            }
            String algorithm = (String) alg;
            //  DebugUtil.trace(JWTUtil.class, "Verifying JWT with algorithm =" + algorithm);
            if (algorithm.equals(NONE_JWT)) {
                return true;
            }
            return false; // so the algorithm does not match up.
        }
        SignedJWT signedJWT = new SignedJWT(header, payload, signature);
        JWSVerifier verifier = null;
        boolean unsupportedProtocol = true;
        if (webKey.isRSAKey()) {
            verifier = new RSASSAVerifier((RSAPublicKey) webKey.publicKey);
            unsupportedProtocol = false;
        }
        if (webKey.isECKey()) {
            verifier = new ECDSAVerifier((ECPublicKey) webKey.publicKey);
            unsupportedProtocol = false;
        }
        if (unsupportedProtocol) {
            throw new UnsupportedProtocolException("unsupported protocol");
        }
        try {
            signedJWT.verify(verifier);
            return true;
        } catch (JOSEException t) {
            return false;
        }
    }

    /**
     * This returns header, payload and signature as the three elements of an array.
     *
     * @param jwt
     * @return
     * @throws IllegalArgumentException if this is not parsable as a token of the form A.B[.C]
     */
    public static String[] decat(String jwt) {
        /*
          Eventually, use JOSE:
          try {
              jwt = JWTParser.parse(string);
          } catch (ParseException e) {
              // Invalid JWT encoding
          }
          returns one of PlainJWT = no signature, SignedJWT = with signature, Encrypted JWT = with encryption.
         */
        StringTokenizer st = new StringTokenizer(jwt, ".");
        // make sure these end up in tjhe right places
        String[] output = new String[3];

        switch (st.countTokens()) {
            case 0:
            case 1:
                throw new IllegalArgumentException("no JWT components found.");
            case 2:
                output[HEADER_INDEX] = st.nextToken();
                output[PAYLOAD_INDEX] = st.nextToken();
                output[SIGNATURE_INDEX] = "";
                break;

            // At this point we do not allow for extra fields
            default:
            case 3:
                output[HEADER_INDEX] = st.nextToken();
                output[PAYLOAD_INDEX] = st.nextToken();
                output[SIGNATURE_INDEX] = st.nextToken();
                break;
/*
            default:
                throw new IllegalArgumentException("Error: Too many JWT components.");
*/
        }
        return output;
    }

    public static final int HEADER_INDEX = 0;
    public static final int PAYLOAD_INDEX = 1;
    public static final int SIGNATURE_INDEX = 2;

    /**
     * This will only peel off the header and payload. No verification of any sort is done!!
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
     *
     * @param jwt
     * @param webKeys
     * @return
     * @throws IllegalArgumentException    if this is not a JWT or the argument is null
     * @throws InvalidAlgorithmException   if there is no algorithm or the algorith is not supported
     * @throws InvalidSignatureException   if the signature fails to verify
     * @throws UnsupportedJWTTypeException if the internal type of the token is not supported
     */
    public static JSONObject verifyAndReadJWT(String jwt, JSONWebKeys webKeys) {
        String[] x = decat(jwt);
        JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[HEADER_INDEX])));
        Base64URL h64 = new Base64URL(x[HEADER_INDEX]);
        Base64URL p64 = new Base64URL(x[PAYLOAD_INDEX]);
        Base64URL s64 = null;
        if (x.length == 3) {
            s64 = new Base64URL(x[SIGNATURE_INDEX]);
        }
        JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[PAYLOAD_INDEX])));
        //    DebugUtil.trace(JWTUtil.class, "header=" + h);
        //     DebugUtil.trace(JWTUtil.class, "payload=" + p);
        if (h.get(ALGORITHM) == null) {
            throw new InvalidAlgorithmException("no algorithm.");
        } else {
            if (h.get(ALGORITHM).equals(NONE_JWT)) {
                DebugUtil.trace(JWTUtil.class, "unsigned id token. Returning payload");

                return p;

            }
        }
        if (!(h.get(TYPE).equals(DEFAULT_TYPE) || h.get(TYPE).equals(RFC9068Constants.HEADER_TYPE)))
            throw new UnsupportedJWTTypeException("Unsupported token type.");
        Object keyID = h.get(KEY_ID);
        //  DebugUtil.trace(JWTUtil.class, "key_id=" + keyID);

        if (keyID == null || !(keyID instanceof String)) {
            throw new InvalidAlgorithmException("Unknown algorithm");
        }
        boolean isOK = false;
        try {
            JSONWebKey wk = webKeys.get(h.getString(KEY_ID));
            if (wk == null) {
                throw new IllegalArgumentException("Web key with id " + KEY_ID + " not found. Allowed keys are " + webKeys.keySet());
            }
            if (wk.publicKey == null) {
                throw new IllegalStateException("Web key with id " + KEY_ID + " does not have a public key");
            }
            isOK = verify(h64, p64, s64, wk);
        } catch (Throwable t) {
            throw new InvalidSignatureException("could not verify signature", t);
        }
        if (!isOK) {
            throw new InvalidSignatureException("could not verify signature");
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
            throw new GeneralException("missing well known URI. Cannot get keys");
        }
        ServiceClient serviceClient = new ServiceClient(URI.create(wellKnown));
        return getJsonWebKeys(serviceClient, wellKnown);
    }

    public static JSONWebKeys getJsonWebKeys(URI wellKnown) {
        if (wellKnown == null) {
            throw new GeneralException("missing well known uri. Cannot resolve the keys");
        }

        return getJsonWebKeys(wellKnown.toString());
    }

    public static JSONObject verifyAndReadJWT(String jwt, URI wellKnown) {
        if (wellKnown == null) {
            throw new GeneralException("missing well known uri. Cannot resolve the keys");
        }
        if (jwt == null || jwt.isEmpty()) {
            throw new GeneralException("missing or empty token.");
        }
        return verifyAndReadJWT(jwt, JWTUtil.getJsonWebKeys(wellKnown.toString()));
    }

    public static JSONWebKeys getJsonWebKeys(ServiceClient serviceClient, String wellKnown) {
        JWKUtil2 jwkUtil21 = new JWKUtil2();
        if (serviceClient == null) {
            throw new GeneralException("missing service client.");
        }
        if (wellKnown == null || wellKnown.isEmpty()) {
            throw new GeneralException("missing well known URI. Cannot get keys");
        }

        // Fix for OAUTH-164, id_token support follows.
        String rawResponse = serviceClient.doGet(wellKnown);
        JSON rawJSON = JSONSerializer.toJSON(rawResponse);

        if (!(rawJSON instanceof JSONObject)) {
            throw new IllegalStateException("Attempted to get JSON Object but returned result is not JSON");
        }
        JSONObject json = (JSONObject) rawJSON;
        String rawKeys = serviceClient.doGet(json.getString("jwks_uri"));
        JSONWebKeys keys = null;
        JSONObject claims = null;
        try {
            keys = jwkUtil21.fromJSON(rawKeys);
        } catch (Throwable e) {
            throw new GeneralException("could not get keys", e);
        }
        return keys;
    }

    /*
     * Strictly for testing.
     * This will take two arguments, a file name containing the keys, the word decode|encode and a string.
     * If the word decode is used, then the string is decoded against the
     *
     * @param args
     */
/*
    public static void main(String[] args) {
        try {
        //    firstTest();
            //   firstTestB();
            //    otherTest();
         //   testSigning();
            JWKUtil2 jwkUtil2 = new JWKUtil2();

            JSONWebKeys kk = jwkUtil2.fromJSON(rawKey);
           System.out.println("Raw key=" + kk);
            JSONWebKeys keys = getJsonWebKeys("https://test.cilogon.org/.well-known/openid-configuration");
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
*/
    // This key was generated by the OIDC compliance test.
//       public static String rawKey = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"jd9bK0aMoFyj1SzbkGgLDwrsV-YqcbTYLjAep2w4Z-K6DlhIznxZBVi7sY2XDFiebJh4dRe453S3ulQHC_bDx8SspzlgBgsL4S4JrSIXSj9pur-CKEAMfYJuvoDG4-j9ILeuRJMUHFv5sA_6_vo3ZwUKU1x-6L-uvnKuuRU8H2O0-YfmbdYG2y3fnT8dgXTJ3s5vhGMAngiJd1iPjJwV37CtraJ4MDtaC_5foifME6TgOfcFc887h6jZtlF8qrQn9pUpXXFBBu-wqjGOSgqpfqpeQueQD1TXN2z9ccNg3I9r7omrs80aSc-3YfreIfxB5qwyOB7S66bRdTOWtealYw\"}]}";

/*
    public static void otherTest() throws Exception {
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File(DebugUtil.getConfigPath()+"/keys.jwk"));
        JSONObject claims = verifyAndReadJWT(ID_TOKKEN, keys);
        System.out.println("claims=" + claims);

    }
*/

/*
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
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File(DebugUtil.getConfigPath()+"/polo-keys.jwk"));

        String idTokken = createJWT(payload, keys.get(keyID));
        System.out.println(idTokken);
        JSONObject claims = verifyAndReadJWT(idTokken, keys);
        System.out.println("claims = " + claims);
        JSONWebKey webKey = keys.get(keyID);
        System.out.println(MyKeyUtil.toX509PEM(webKey.publicKey));
    }
*/

/*
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
*/

  /*  public static void signAndVerify(JSONWebKeys keys, String keyID) throws Exception {
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
*/
 /*   public static void generateAndSign() throws Exception {
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
        JSONWebKeys keys2 = jwkUtil2.fromJSON(jsonKeys.toString(2));

        JSONWebKey webKey = keys2.get(keyID);
        System.out.println("Serializing, deserializing then signing.");

        signAndVerify(keys2, keyID);

    }
*/

  /*  public static void printKeys() throws Exception {
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


        JSONObject jsonKeys = jwkUtil2.toJSON(keys);
        JSONWebKeys keys2 = jwkUtil2.fromJSON(jsonKeys.toString(2));

        JSONWebKey webKey = keys2.get(keyID);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(webKey.privateKey.getEncoded());
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);

        System.out.println(MyKeyUtil.toX509PEM(webKey.publicKey));
        System.out.println(MyKeyUtil.toPKCS1PEM(privateKey));
        System.out.println(MyKeyUtil.toPKCS8PEM(privateKey));

    }
*/
  /*  public static void firstTestB() throws Exception {
        String keyID = "9k0HPG3moXENne";
        JSONWebKeys keys = jwkUtil2.fromJSON(new File(DebugUtil.getConfigPath()+"/keys.jwk"));

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
*/
 /*   public static void testSigningDirectly() throws Exception {
        String keyID = "9k0HPG3moXENne";
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File(DebugUtil.getConfigPath()+"/keys.jwk"));

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
*/
 /*   public static void testJWT_IO() throws Exception {
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
        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(new File(DebugUtil.getConfigPath()+"/keys.jwk"));

        JSONWebKey jsonWebKey = keys.get(keyID);
        JSONObject h = JSONObject.fromObject(header);
        JSONObject p = JSONObject.fromObject(payload);
        String signature = sign(h, p, jsonWebKey);
        System.out.println(signature);

    }
*/
    //  public static String ID_TOKKEN = "eyJ0eXAiOiJKV1QiLCJraWQiOiI5azBIUEczbW9YRU5uZSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJodHRwczovL2FzaGlnYXJ1Lm5jc2EudWl1Yy5lZHU6OTQ0MyIsInN1YiI6ImpnYXlub3IiLCJleHAiOjE0ODQ3NjQ3NDQsImF1ZCI6Im15cHJveHk6b2E0bXAsMjAxMjovY2xpZW50X2lkLzE0NjQ5ZTJmNDY4NDUwZGFjMGMxODM0ODExZGJkNGM3IiwiaWF0IjoxNDg0NzYzODQ0LCJub25jZSI6IjBaSWktRXV4ZUNfWDhBZ0IzVmlmT29xS2lYV3N6X05sWFN6SXU3aDhyelUiLCJhdXRoX3RpbWUiOiIxNDg0NzYzODQzIn0.PXxUPRJ1aPQmcgfidz1xf28Ip3g3TCWldAPT25JVhsu5kJw75mDjPFVaHvcGOnxO121PAlisQlqARqpx3ytW720odRHEhv3JmVjvoRyKeCHzAP7va75cZmgOWDUI9SONDuNcuomRbUrRyLwrgH2CtBrKr05AowYojkJspRf3a5z6K5s-6ahbUlm7AAmYFDceNtQBeiutCZBfP4_gMLAxdQb7pHfyocKslAV0CwtAKYvqUpkIHuUYsc5CXYuan2Ox0If_pMJC4uV3Ov4banMNLwKeQPRUyWhHLnhrMl5KeoaEtL2nW4X7JIqK8EX-esmjQmr_NVI7DP8DV1C3OjHkpA";

}
