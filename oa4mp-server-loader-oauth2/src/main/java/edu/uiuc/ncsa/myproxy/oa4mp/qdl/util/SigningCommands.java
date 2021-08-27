package edu.uiuc.ncsa.myproxy.oa4mp.qdl.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import net.sf.json.JSONObject;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
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

    public static final String RS_256 = "RS256";
    public static final String RS_384 = "RS384";
    public static final String RS_512 = "RS512";

    public SigningCommands(OA2SE oa2se) {
        super(oa2se == null ? null : oa2se.getMyLogger());
        this.oa2SE = oa2se;
    }

    public OA2SE getOa2SE() {
        return oa2SE;
    }

    OA2SE oa2SE;

    @Override
    public String getPrompt() {
        return "keys>";
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

        if (1 < inputLine.size()) {
            // a lot of command utils specify the fiule with this flag. Since everyone keeps
            // sending this, allow for it (otherwise people create a key file called -file in the
            // invocation directory, which is not intuitive and therefore not findable afterwards).
            if(inputLine.hasArg("-file")){
                publicKeyFile = new File(inputLine.getNextArgFor("-file"));
            }else {
                publicKeyFile = new File(inputLine.getArg(1));
            }
        }
        if (publicKeyFile == null && isBatchMode()) {
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
                    sayi("Sorry, but you must supply the name of the file as well (or type 'exit' to exit");
                } else {
                    if (!isBatchMode()) {
                        retry = !isOk(readline("The file you gave exists, do you want to over write it? [y/n]"));
                    }
                }
            } else {
                retry = false;
            }
        }
        if (!isBatchMode()) {
            if (!isOk(readline("create a new set of JSON web keys to \"" + publicKeyFile.getAbsolutePath() + "\"?[y/n]"))) {
                say("create cancelled.");
                return;
            }

        }

        JSONWebKeys keys = createJsonWebKeys();
        FileWriter writer = new FileWriter(publicKeyFile);
        JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
        writer.write(jwks.toString(2));
        writer.flush();
        writer.close();

        if (!isBatchMode()) {
            sayi("JSONweb keys written");
            sayi("Done!");
        }

    }

    /**
     * This should probably move to {@link JSONWebKeyUtil}.
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static JSONWebKeys createJsonWebKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        JSONWebKeys keys = new JSONWebKeys(null);
        keys.put(createJWK(RS_256));
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
                targetFile  = new File(inputLine.getNextArgFor(SYMMETRIC_KEY_FILE_ARG));
            } catch (Throwable t) {
                // rock on
            }
        }

        byte[] array = null;
        if (!isBatchMode() && targetFile== null) {
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
            if(targetFile != null){
                keys.add(output);
            }else {
                say(output);
            }

        }
        if(targetFile != null){
            try {
                Files.write(targetFile.toPath(), keys);
                say("Done. Wrote " + count + " key" + (count==1?"":"s") + " to " + targetFile);
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

    public static JSONWebKey createJWK(String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
        byte[] byteArray = new byte[16];
        random.nextBytes(byteArray);
        String id = DatatypeConverter.printHexBinary(byteArray);

        KeyPair keyPair = KeyUtil.generateKeyPair();
        JSONWebKey webKey = new JSONWebKey();
        webKey.publicKey = keyPair.getPublic();
        webKey.privateKey = keyPair.getPrivate();
        webKey.use = "sig";
        webKey.id = id;
        webKey.algorithm = algorithm;
        webKey.type = "RSA"; //only one supported
        return webKey;
    }
}
