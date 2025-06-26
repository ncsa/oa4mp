package org.oa4mp.server.loader.qdl.util;

import org.oa4mp.server.loader.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.HelpUtil;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/6/17 at  9:27 AM
 */
public class SigningCommands extends CommonCommands {
    @Override
    public void bootstrap(InputLine inputLine) throws Throwable {
        // no-op at this point
    }

    @Override
    public HelpUtil getHelpUtil() {
        return null;
    }

    public static final String RS_256 = "RS256";
    public static final String RS_384 = "RS384";
    public static final String RS_512 = "RS512";

    public SigningCommands(OA2SE oa2se) throws Throwable {
        super(oa2se == null ? null : oa2se.getMyLogger());
        this.oa2SE = oa2se;
    }

    public OA2SE getOa2SE() {
        return oa2SE;
    }

    OA2SE oa2SE;

    @Override
    public String getName() {
        return "keys";
    }

    @Override
    public String getPrompt() {
        return getName()+">";
    }

    protected void createHelp() {
        say("create [path]: This will allow you to create a completely new set of JSON web keys and write it to a file");
        say("       If the path is given, the keys will be written. If the path is not given then you will be");
        say("       prompted for one. This will not overwrite an existing file.");
    }

    public void create(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createHelp();
            return;
        }
        //PublicKey publicKey = KeyUtil.g
        boolean retry = true;
        File publicKeyFile = null;
        boolean isInteractive = true;
        if (inputLine.size() == 1  || inputLine.size() == 2 && inputLine.hasArg("-single")) {
            boolean singleKeyOnly = inputLine.hasArg("-single");
            JSONWebKeys keys = createJsonWebKeys();
            StringWriter writer = new StringWriter();
            JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
            if(singleKeyOnly){
                JSONArray array = jwks.getJSONArray("keys");
                JSONObject key = null;
                for(int i = 0 ; i < array.size(); i++){
                      if(array.getJSONObject(i).getString("alg").equals( "RS256")){
                          key = array.getJSONObject(i);
                          break;
                      }
                }
                jwks = new JSONObject();
                JSONArray array1 = new JSONArray();
                array1.add(key);
                jwks.put("keys", array1);
            }
            writer.write(jwks.toString(2));
            writer.flush();
            writer.close();
            say(writer.toString());
            return;
        }
        if (1 < inputLine.size()) {
            // a lot of command utils specify the file with this flag. Since everyone keeps
            // sending this, allow for it (otherwise people create a key file called -file in the
            // invocation directory, which is not intuitive and therefore not findable afterwards).
            if (inputLine.hasArg("-file")) {
                publicKeyFile = new File(inputLine.getNextArgFor("-file"));
            } else {
                publicKeyFile = new File(inputLine.getArg(1));
            }
        }
        if (publicKeyFile == null ) {
            throw new GeneralException("No full path to the file given.");
        }

        while (retry) {
            if (publicKeyFile == null) {
                String publicKeyPath = getInput("Give the file path", "");
                if (publicKeyPath.toLowerCase().equals("exit") || publicKeyPath.toLowerCase().equals("quit")) {
                    return;
                }
                publicKeyFile = new File(publicKeyPath);
            }


            if (publicKeyFile.exists()) {
                if (!publicKeyFile.isFile()) {
/*
                    sayi("Sorry, but you must supply the name of the file as well (or type 'exit' to exit");
                } else {
                    if (!isBatchMode()) {
*/
                        retry = !isOk(readline("The file you gave exists, do you want to over write it? [y/n]"));
//                    }
                }
            } else {
                retry = false;
            }
        }
  //      if (!isBatchMode()) {
            if (!isOk(readline("create a new set of JSON web keys to \"" + publicKeyFile.getAbsolutePath() + "\"?[y/n]"))) {
                say("create cancelled.");
                return;
            }

    //    }

        JSONWebKeys keys = createJsonWebKeys();
        FileWriter writer = new FileWriter(publicKeyFile);
        JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
        writer.write(jwks.toString(2));
        writer.flush();
        writer.close();

      //  if (!isBatchMode()) {
            sayi("JSONweb keys written");
            sayi("Done!");
        //}

    }

    /**
     * These are done as per <a href="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3">https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3</a>
     *
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static JSONWebKeys createRSAJsonWebKeys(int size, String defaultKeyID) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKey defaultKey = createRSAJWK(size, RS_256);
        if(defaultKeyID != null){
            defaultKey.id = defaultKeyID;
        }
        JSONWebKeys keys = new JSONWebKeys(defaultKey.id);
        keys.put(defaultKey);
        keys.put(createRSAJWK(size, RS_384));
        keys.put(createRSAJWK(size, RS_512));
        return keys;
    }

    /**
     * Note that these are done as per
     * <href a="https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4">https://www.rfc-editor.org/rfc/rfc7518.html#section-3.4</href>
     * and generate the basic set of all elliptic curves
     *
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static JSONWebKeys createECJsonWebKeys(String defaultKeyID) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKey defaultKey = createECJWK(JWKUtil2.EC_CURVE_P_256, JWKUtil2.ES_256);
        if(defaultKeyID != null){
            defaultKey.id = defaultKeyID;
        }
        JSONWebKeys keys = new JSONWebKeys(defaultKey.id);
        keys.put(defaultKey);
        keys.put(createECJWK(JWKUtil2.EC_CURVE_P_384, JWKUtil2.ES_384));
        keys.put(createECJWK(JWKUtil2.EC_CURVE_P_521, JWKUtil2.ES_512));
        return keys;
    }

    /**
     * Create a set of keys for a given curve using the 3 standard signing algorithms. If the parameter is
     * trivial, then it returns the default as per {@link #createECJsonWebKeys()};
     *
     * @param curve
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     */
    public static JSONWebKeys createECJsonWebKeys(String curve, String defaultKeyID) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        if (StringUtils.isTrivial(curve)) {
            return createECJsonWebKeys(defaultKeyID);
        }
        JSONWebKey defaultKey = createECJWK(curve, JWKUtil2.ES_256);
        if(defaultKeyID != null){
            defaultKey.id = defaultKeyID;
        }
        JSONWebKeys keys = new JSONWebKeys(defaultKey.id);
        keys.put(defaultKey);
        keys.put(createECJWK(curve, JWKUtil2.ES_384));
        keys.put(createECJWK(curve, JWKUtil2.ES_512));
        return keys;

    }

    public static JSONWebKeys createJsonWebKeys() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        JSONWebKey defaultKey = createJWK(RS_256);
        JSONWebKeys keys = new JSONWebKeys(defaultKey.id);
        keys.put(defaultKey);
        keys.put(createJWK(RS_384));
        keys.put(createJWK(RS_512));
        return keys;
    }

    public int defaultSymmetricKeyLength = 256;
    public String SYMMETRIC_KEY_ARG = "-length";
    public String SYMMETRIC_KEY_COUNT_ARG = "-count";
    public String SYMMETRIC_KEY_FILE_ARG = "-out";

    protected void showSymmetricKeyHelp() {
        say("createSymmetricKey [" + SYMMETRIC_KEY_ARG + " len + | " + SYMMETRIC_KEY_COUNT_ARG + "count] " +
                "This will create a key for use as a symmetric key, i.e., this will produce");
        say("   a base 64 encoded sequence of random bytes to be used as a symmetric key for");
        say("   the given length. If no length is included, the default of " + defaultSymmetricKeyLength + " bytes is used.");
        say("   If the " + SYMMETRIC_KEY_COUNT_ARG + " is given, this will produce that many keys");
        say("   If the " + SYMMETRIC_KEY_FILE_ARG + " is given, this will write the keys to the given file, one per line.");

    }

    public void create_symmetric_keys(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSymmetricKeyHelp();
            return;
        }

        int length = defaultSymmetricKeyLength;
        if (inputLine.hasArg(SYMMETRIC_KEY_ARG)) {
            try {
                length = Integer.parseInt(inputLine.getNextArgFor(SYMMETRIC_KEY_ARG));
            } catch (Throwable t) {
                // rock on
            }
        }
        int count = 1;
        if (inputLine.hasArg(SYMMETRIC_KEY_COUNT_ARG)) {
            try {
                count = Integer.parseInt(inputLine.getNextArgFor(SYMMETRIC_KEY_COUNT_ARG));
            } catch (Throwable t) {
                // rock on
            }
        }
        File targetFile = null;
        if (inputLine.hasArg(SYMMETRIC_KEY_FILE_ARG)) {
            try {
                targetFile = new File(inputLine.getNextArgFor(SYMMETRIC_KEY_FILE_ARG));
            } catch (Throwable t) {
                // rock on
            }
        }

        byte[] array = null;
        if (targetFile == null) {
            say(count + " base 64 encoded key" + (count == 1 ? "" : "s") + " with length of " + length + " bytes:\n");
        }
        List<String> keys = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            array = new byte[length];

            random.nextBytes(array);
            String output = Base64.getEncoder().encodeToString(array);

            while (output.endsWith("=")) {
                output = output.substring(0, output.length() - 2);
            }
            if (targetFile != null) {
                keys.add(output);
            } else {
                say(output);
            }

        }
        if (targetFile != null) {
            try {
                Files.write(targetFile.toPath(), keys);
                say("Done. Wrote " + count + " key" + (count == 1 ? "" : "s") + " to " + targetFile);
            } catch (IOException e) {
                say("Could not write keys to " + targetFile + ":" + e.getMessage());
            }
        }
    }

    /**
     * <b>NOTE</b> that good practice is to set the secure random source to something truly random
     * by setting the  java.security.egd property for the JVM. On unix systems this would look like
     * <code>java -Djava.security.egd=file:/dev/urandom</code>
     */
    static SecureRandom random = new SecureRandom();

    public static JSONWebKey createJWK(String algorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return createRSAJWK(2048, algorithm); // create an RSA key
    }

    public static JSONWebKey createRSAJWK(int size, String algorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return getJwkUtil2().createRSAKey(size, algorithm);
    }

    public static JWKUtil2 getJwkUtil2() {
        if (jwkUtil2 == null) {
            jwkUtil2 = new JWKUtil2();
        }
        return jwkUtil2;
    }

    public static void setJwkUtil2(JWKUtil2 newJWKUtil2) {
        jwkUtil2 = newJWKUtil2;
    }

    protected static JWKUtil2 jwkUtil2;

    public static JSONWebKey createECJWK(String curve, String algorithm) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        return getJwkUtil2().createECKey(curve, algorithm);

    }

    public static JSONWebKey createJWK(String algorithm, boolean isRSA) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        if (isRSA) {
            return getJwkUtil2().createRSAKey(2048, algorithm);
        }
        return getJwkUtil2().createECKey("P-256", algorithm);
/*

        KeyPair keyPair = KeyUtil.generateKeyPair();
        JSONWebKey webKey = new JSONWebKey();
        webKey.publicKey = keyPair.getPublic();
        webKey.privateKey = keyPair.getPrivate();
        webKey.use = "sig";
        webKey.id = id;
        webKey.algorithm = algorithm;
        webKey.type = "RSA"; //only one supported
        return webKey;
*/
    }
}
