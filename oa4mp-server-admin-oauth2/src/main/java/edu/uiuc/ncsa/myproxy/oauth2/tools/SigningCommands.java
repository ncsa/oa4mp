package edu.uiuc.ncsa.myproxy.oauth2.tools;

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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/6/17 at  9:27 AM
 */
public class SigningCommands extends CommonCommands {
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
            publicKeyFile = new File(inputLine.getArg(1));
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
                    if(!isBatchMode()) {
                        sayi2("The file you gave exists, do you want to over write it? [y/n]");
                        retry = !isOk(readline());
                    }
                }
            } else {
                retry = false;
            }
        }
        if (!isBatchMode()) {
            sayi2("create a new set of JSON web keys?[y/n]");
            if (!isOk(readline())) {
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

    public JSONWebKeys createJsonWebKeys() throws NoSuchProviderException, NoSuchAlgorithmException {
        JSONWebKeys keys = new JSONWebKeys(null);
        keys.put(createJWK("RS256"));
        keys.put(createJWK("RS384"));
        keys.put(createJWK("RS512"));
        return keys;
    }

    protected int defaultSymmetricKeyLength = 256;
    protected String SYMMETRIC_KEY_ARG = "-length";

    protected void showSymmetricKeyHelp() {
        say("createSymmetricKey [" + SYMMETRIC_KEY_ARG + " len] This will create a key for use as a symmetric key, i.e., this will produce");
        say("   a base 64 encoded sequence of random bytes to be used as a symmetric key for");
        say("   the given length. If no length is included, the default of " + defaultSymmetricKeyLength + "bytes is used.");
    }

    public void create_symmetric_key(InputLine inputLine) {
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
        byte[] array = new byte[length];
        random.nextBytes(array);
        if (!isBatchMode()) {
            say("Base encoded key of length " + length);
        }
        say(Base64.getEncoder().encodeToString(array));
    }

    /**
     * <b>NOTE</b> that good practice is to set the secure random source to something truly random
     * by setting the  java.security.egd property for the JVM. On unix systems this would look like
     * <code>java -Djava.security.egd=file:/dev/urandom</code>
     */
    SecureRandom random = new SecureRandom();

    protected JSONWebKey createJWK(String algorithm) throws NoSuchProviderException, NoSuchAlgorithmException {
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
