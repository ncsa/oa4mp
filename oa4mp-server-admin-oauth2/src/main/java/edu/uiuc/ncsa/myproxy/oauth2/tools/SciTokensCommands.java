package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.URI;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.JWTUtil.decat;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/6/17 at  3:47 PM
 */
public class SciTokensCommands extends CommonCommands {


    public SciTokensCommands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "sciTokens>";
    }

    public static String JWK_EXTENSION = "jwk";

    public void create_keys(InputLine inputLine) throws Exception {
        SigningCommands sg = new SigningCommands(null);
        sg.create(inputLine);

    }

    JSONWebKeys keys = null;

    String wellKnown = null;
    public void set_well_known(InputLine inputLine) throws Exception{

    }
    protected void setKeysHelp() {
        say("set_keys: [-file filename | uri]");
        say("          Set the keys used for signing and validation in this session.");
        say("          Either supplied a fully qualified path to the file or a uri. If you pass nothing");
        say("          prompted for a file. You can invoke this at any to change the keys.");
        say("  Related: create_keys");
    }

    /**
     * Set the keys to be used for signing and validation.
     *
     * @param inputLine
     * @throws Exception
     */
    public void set_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            setKeysHelp();
            return;
        }
        if(inputLine.hasArg("-file")) {

            File f = new File(inputLine.getArg(1));
            if (!f.exists()) {
                say("Sorry, the file you specified, \"" + (inputLine.getArg(1)) + "\" does not exist.");
                return;
            }
            keys = readKeys(f);
            if (defaultKeyID != null) {
                if (keys.containsKey(defaultKeyID)) {
                    keys.setDefaultKeyID(defaultKeyID);
                }
            }
        }else{
            wellKnown = inputLine.getArg(1);
            try {
                keys = JWTUtil.getJsonWebKeys(new ServiceClient(URI.create("https://scitokens.org")), wellKnown);
            }catch(Throwable t){
                             t.printStackTrace();
                throw t;
            }
        }
    }

    protected JSONWebKeys readKeys(File file) throws Exception {
        return JSONWebKeyUtil.fromJSON(file);
    }

    @Override
    protected void say(String x) {
        // suppress output if this is run from the command line.
        if (!isBatchMode()) {
            super.say(x);
        }
    }

    protected void listKeysHelp() {
        say("list_keys:This will list all the public keys in the key file in pem format.");
        say("           Each key will be preceeded by its unique ID in the key file.");
        say("           You may invoke this with no argument, in which case the default key file");
        say("           as set in the set_keys command will be used, or you can supply a fully qualified");
        say("           path to a JSON web key file that will be used.");
        say("  Related: set_keys, create_keys");
    }

    protected String readFile(String filename) throws Exception {
        File f = new File(filename);
        if (!f.exists()) {
            return null;
        }
        FileReader fr = new FileReader(f);
        BufferedReader br = new BufferedReader(fr);
        String output = "";
        String currentLine = br.readLine();
        while (currentLine != null) {
            output = output + currentLine;
            currentLine = br.readLine();
        }
        br.close();
        return output;
    }

    public void list_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            listKeysHelp();
            return;
        }
        JSONWebKeys localKeys = null;
        if (1 == inputLine.size()) {
            // try to use the defined keys
            if (keys == null || keys.isEmpty()) {
                say("Sorry, there are no keys specified. Either use setkeys or specify a key file.");
                return;
            }

            localKeys = keys;
        } else {
            File publicKeyFile = new File(inputLine.getArg(1));
            localKeys = readKeys(publicKeyFile);
        }
        boolean hasDefault = localKeys.hasDefaultKey();
        String defaultKey = null;
        if (hasDefault) {
            defaultKey = localKeys.getDefaultKeyID();
        }
        for (String key : localKeys.keySet()) {
            if (hasDefault) {
                if (key.equals(defaultKey)) {
                    say("key id=" + key + " (default)");
                } else {
                    say("key id=" + key);
                }
            } else {
                say("key id=" + key);
            }
            say(KeyUtil.toX509PEM(localKeys.get(key).publicKey));
        }

    }


    protected void printCreateClaimsHelp() {
        say("create_claims: Prompt the user for key/value pairs and build a claims object. ");
        say("               This will write the object to a file for future use.");
        say("");
        say("Related: parse_claims");
    }

    /**
     * Create a set of claims and write them to a file in JSON format.
     *
     * @param inputLine
     * @throws Exception
     */
    public void create_claims(InputLine inputLine) throws Exception {
        say("Enter a key then a value when prompted. You can enter multiple values separated by commas");
        say("Just hit return (no value) to exit");
        boolean isDone = false;
        JSONObject jsonObject = new JSONObject();
        while (!isDone) {
            String key = getInput("Enter key or return to exit.");
            if (isEmpty(key)) {
                isDone = true;
                continue;
            }
            String value = getInput("Enter value. multiple values should be comma separated");
            if (0 < value.indexOf(",")) {
                StringTokenizer st = new StringTokenizer(value, ",");
                JSONArray array = new JSONArray();
                while (st.hasMoreTokens()) {
                    array.add(st.nextToken());
                }
                jsonObject.put(key, array);
            } else {
                jsonObject.put(key, value);
            }
        }
        say(jsonObject.toString());
        String writeToFile = getInput("Would you like to write this to a file?", "false");
        Boolean isWrite = Boolean.parseBoolean(writeToFile);
        if (isWrite) {
            String fileName = getInput("Enter filename");
            File f = new File(fileName);
            if (f.exists()) {
                String overwrite = getInput("This file exists. Do you want to overwrite it?", "false");
                if (Boolean.parseBoolean(overwrite)) {

                } else {

                }
            }
        }
    }


    protected boolean getBooleanInput(String prompt) {
        String x = getInput(prompt, "y");
        if (x.equalsIgnoreCase("y") || x.equalsIgnoreCase("yes") || x.equalsIgnoreCase("true")) return true;
        return false;
    }

    protected String getInput(String prompt) {
        sayi2(prompt + ":");
        String inLine = readline();
        if (isEmpty(inLine)) {
            return null; // no input. User hit a return
        }
        return inLine;
    }


    String defaultKeyID = null;

    protected void printSetDefaultIDHelp() {
        say("set_default_id [keyid]: This will set the default key id to be used for all signing and verification.");
        say("                        If this is not set, you will be prompted each time for an id.");
    }

    public void set_default_id(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createTokenHelp();
            return;
        }
        if (1 < inputLine.size()) {
            defaultKeyID = inputLine.getArg(1);
            return;
        }
        String x = getInput("Enter the key id");
        // do nothing if there is no value supplied.
        if (isEmpty(x)) {
            return;
        }
        defaultKeyID = x;

    }

    protected void printParseClaimsHelp() {
        say("parse_claims [filename]");
        say("           Read a file and print out if it parses as JSON.");
        say("           If the filename is omitted, you will be prompted for it.");
        say("           Note that this will try to give some limited feedback in syntax errors.");
        say("Related: create_claims");
    }

    /**
     * Read the claims in a file and verify that they are a valid JSON object.
     *
     * @param inputLine
     * @throws Exception
     */
    public void parse_claims(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printParseClaimsHelp();
            return;
        }
        String filename = null;
        if (1 < inputLine.size()) {
            filename = inputLine.getArg(1);
        } else {
            filename = getInput("Enter full path to the claims file.");
            if (isEmpty(filename)) {
                say("No claims file. Exiting...");
                return;
            }
        }
        String rawJSON = readFile(filename);
        if (rawJSON == null) {
            say("Could not read the file \"" + filename + "\"");
            return;
        }
        JSON jsonObject = null;
        try {
            jsonObject = JSONObject.fromObject(rawJSON);
        } catch (Throwable t) {
            say("Parsing fail with a message of \"" + t.getMessage() + "\"");
            return;
        }
        if (jsonObject != null) {
            say("success!");
            say(jsonObject.toString(3));
        } else {
            say("No JSON object resulted from parsing.");
        }
    }


    /**
     * This will take an input line and search for the arg, returning the next value.
     * E.g. if the input line is  "-file y -id z -v"
     * then supplying "-file" as the key here will return "y".
     * If there is no such key, then a null is returned.
     *
     * @param inputLine
     * @param key
     * @return
     */
    protected String getArgValue(InputLine inputLine, String key) {
        int index = inputLine.indexOf(key);
        if (index == -1) return null;
        // Remember that the input line has the name of the method as the zeroth argument, so
        // it is always at least 1 in length
        if (inputLine.size() + 1 == index) {
            //then this is the final argument and nothing follows
            return null;
        }
        return inputLine.getArg(index + 1);
    }

    protected void createTokenHelp() {
        say("create_token [-file claims -keys keyfile -keyid id]");
        say("              This will take the current keys (uses default) and a file containing a JSON");
        say("              format set of claims. It will then sign the claims with the right headers etc.");
        say("              and print out the results to the console. Any of the arguments omitted will cause you");
        say("              to be prompted. If you have already set the key and keyid these will be used.");
        say("");
        say("Related: set_keys, set_default_id");
    }

    String lastToken = null;

    public void create_token(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createTokenHelp();
            return;
        }
        // pull off the command line arguments

        JSONWebKeys localKeys = null;
        if (inputLine.hasArg("-keys")) {
            String fileName = getArgValue(inputLine, "-keys");
            File f = new File(fileName);
            if (!f.exists()) {
                say("Sorry, that file does not seem to exist");
                return;
            }
            if (!f.isFile()) {
                say("Sorry, the thing yo specified is not a file.");
                return;
            }
            localKeys = readKeys(f);
        } else {
            if (keys == null || keys.isEmpty()) {
                if (getBooleanInput("No keys set. Would you like to specify keys for signing?")) {
                    String x = getInput("Enter fully qualified path and file name");
                    if (isEmpty(x)) {
                        say("no file entered, exiting...");
                        return;
                    }
                    localKeys = readKeys(new File(x));
                }

            } else {
                localKeys = keys;
            }
        }
        String localDefaultID = null;
        if (inputLine.hasArg("-id")) {
            localDefaultID = getArgValue(inputLine, "-id");
        } else {
            if (defaultKeyID != null) {
                localDefaultID = defaultKeyID;
            } else {
                if (getBooleanInput("No key id found. Do you want to enter one?")) {
                    localDefaultID = getInput("Enter key id:");
                } else {
                    return;
                }
            }
        }
        JSONObject claims = null;
        if (inputLine.hasArg("-file")) {
            claims = JSONObject.fromObject(readFile(getArgValue(inputLine, "-file")));
        } else {
            String x = getInput("Enter the name of the file containing the JSON object to use:");
            if (isEmpty(x)) {
                say("No argument, exiting...");
                return;
            }
            claims = JSONObject.fromObject(readFile(x));

        }
        String signedToken = JWTUtil.createJWT(claims, localKeys.get(localDefaultID));
        lastToken = signedToken;
        say(signedToken);
    }

    protected void printTokenHelp() {
        say("print_token: Print the last token generated by the create_token call.");
        say("             If there is no token, that will be shown too. ");
        say("   Related: create_token");
    }

    public void print_token(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printTokenHelp();
            return;
        }
        if (lastToken == null) {
            say("(no token has been created)");
            return;
        }
        say(lastToken);
    }

    protected void printListKeyIDs() {
        say("list_key_ids [filename]");
        say("                List the unique key ids in the file");
        say("                If you do not supply an argument, the globally set keys will be used");
        say("                If there is no default set of keys, you will be prompted for a file");
        say("      related: set_keys, set_default_id");
    }

    public void list_key_ids(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printListKeyIDs();
            return;
        }
        JSONWebKeys jsonWebKeys = null;
        if (1 < inputLine.size()) {
            jsonWebKeys = JSONWebKeyUtil.fromJSON(new File(inputLine.getArg(1)));
        } else {
            if (keys == null) {
                if (getBooleanInput("Do you want to enter a file name?")) {
                    String x = getInput("Enter path and name of the key file");
                    jsonWebKeys = JSONWebKeyUtil.fromJSON(new File(x));
                } else {
                    return;
                }
            } else {
                jsonWebKeys = keys;

            }
        }
        String defaultWebKey = null;
        if (jsonWebKeys.hasDefaultKey()) {
            defaultWebKey = jsonWebKeys.getDefaultKeyID();
        } else {
            defaultWebKey = defaultKeyID;
        }
        for (String keyID : jsonWebKeys.keySet()) {
            JSONWebKey webKey = jsonWebKeys.get(keyID);
            boolean isDefault = webKey.id.equals(defaultWebKey);
            say("id=" + keyID + ", alg=" + webKey.algorithm + ", type=" + webKey.type + ", use=" + webKey.use + (isDefault ? " (default)" : ""));
        }
    }

    protected void printValidateTokenHelp() {
        say("validate_token [-file filename] | string");
        say("         This will take a token and check the signature. It will also print out the payload");
        say("         and header information.");
        say("         You may supply either the token itself or specify with the -file flag that this is in a file.");
        say("   related: create_token");
    }

    public void validate_token(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printValidateTokenHelp();
            return;
        }
        String token = null;
        if (1 == inputLine.size()) {
            say("Sorry, no argument");
            return;
        }
        if (inputLine.hasArg("-file")) {
            token = getArgValue(inputLine, "-file");
        } else {
            token = inputLine.getArg(1);
        }
        String[] x = decat(token);
        JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[0])));
        JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[1])));
        say("header=" + h);
        say("payload=" + p);
        if (JWTUtil.verify(h, p, x[2], keys.get(defaultKeyID))) {
            say("token valid!");
        } else {
            say("could not validate token");
        }
    }
}

