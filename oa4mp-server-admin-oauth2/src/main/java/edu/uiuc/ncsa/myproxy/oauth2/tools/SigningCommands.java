package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
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

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/6/17 at  9:27 AM
 */
public class SigningCommands extends CommonCommands {
    public SigningCommands(OA2SE oa2se) {
        super(oa2se.getMyLogger());
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
        say("create: This will allow you to create a completely new set of JSON web keys and write it to a file");
    }

    public void create(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createHelp();
            return;
        }
        //PublicKey publicKey = KeyUtil.g
        boolean retry = true;
        File publicKeyFile = null;
        File privateKeyFile = null;
        while (retry) {
            String publicKeyPath = getInput("Give the file path", "");
            if (publicKeyPath.toLowerCase().equals("exit") || publicKeyPath.toLowerCase().equals("quit")) {
                return;
            }
            publicKeyFile = new File(publicKeyPath);

            if (publicKeyFile.exists()) {
                if (!publicKeyFile.isFile()) {
                    sayi("Sorry, but you must supply the name of the file as well (or type 'exit' to exit");
                } else {
                    sayi2("The file you gave exists, do you want to over write it? [y/n]");
                    retry = !isOk(readline());
                }
            } else {
                retry = false;
            }
        }

        retry = true;

        sayi2("create a new set of JSON web keys?[y/n]");

        if (!

                isOk(readline()

                ))

        {
            say("create cancelled.");
            return;
        }

        JSONWebKeys keys = new JSONWebKeys(null);
        keys.put(

                createJWK("RS256")

        );
        keys.put(

                createJWK("RS384")

        );
        keys.put(

                createJWK("RS512")

        );


        FileWriter writer = new FileWriter(publicKeyFile);
        JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
        writer.write(jwks.toString(3));
        writer.flush();
        writer.close();

        sayi("JSONweb keys written");

        sayi("Done!");

    }

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
