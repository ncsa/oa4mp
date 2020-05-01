package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.qdl.util.FileUtil;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.JWTUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims;
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

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Date;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.JWTUtil.decat;
import static edu.uiuc.ncsa.security.oauth_2_0.JWTUtil.getJsonWebKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/6/19 at  2:39 PM
 */
public class JWKUtilCommands extends CommonCommands {
    // END OF Batch File processing stuff.

    public JWKUtilCommands(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getPrompt() {
        return "jwt>";
    }

    public static String JWK_EXTENSION = "jwk";

    protected void createKeysHelps() {
        say("create_keys [" + CL_INPUT_FILE_FLAG + " set_of_keys " + CL_IS_PUBLIC_FLAG + "] | [" + CL_IS_PRIVATE_FLAG + "] " + CL_OUTPUT_FILE_FLAG + " file");
        sayi("Create a set of RSA JSON Web keys and store them in the given file");
        sayi("There are several modes of operation. If you do not specify an output file, then the keys are written ");
        sayi("to the command line.");
        sayi("Interactive mode:");
        sayi("   E.g.");
        sayi("   create_keys " + CL_OUTPUT_FILE_FLAG + " keys.jwk");
        sayi("       This will create a set of key pairs with random ids and store the result in the file kwys.jwk");
        sayi("   create_keys");
        sayi("        with no arguments, a full set of keys will be created and printed to the command line.");
        sayi("   ");
        sayi("Batch mode:");
        sayi("   You can also take a set of keys and extract the set of public keys. Various JWT toolkits require this.");
        sayi("   create_keys " + CL_IS_PUBLIC_FLAG + " " + CL_INPUT_FILE_FLAG + " keys.jwk " + CL_OUTPUT_FILE_FLAG + "  pub_keys.jwk");
        sayi("        This will take the full set of keys in keys.jwk extract the public keys and place the result in pub_keys.jwk");
        sayi("        Note: including the -public flag implies the -in argument is given and an error will result if it is not found");
        say("See also create_public_keys");
    }

    /**
     * Generate and add keys to an existing key set. If the key set is empty or missing, it will be created.
     * Note that this generates full sets of keys. If a file is specified, then that will be updated rather than
     * the currently active set of keys.
     *
     * @param inputLine
     * @throws Exception
     */
    public void add_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            addKeysHelps();
            return;
        }
        boolean hasInputFile = inputLine.hasArg(CL_INPUT_FILE_FLAG);
        boolean hasOutputFile = inputLine.hasArg(CL_OUTPUT_FILE_FLAG);
        boolean isPublic = inputLine.hasArg(CL_IS_PUBLIC_FLAG);
        // if this is set, they got confused and should be prompted.
        if (isPublic) {
            say("warning: This will create a new set of public and private keys. ");
            if (!"y".equalsIgnoreCase(getInput("Do you want to continue?[y/n]"))) {
                say("aborted...");
                return;
            }
        }
        JSONWebKeys sourceKeys = this.keys;
        if (hasInputFile) {
            String contents = readFile(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
            sourceKeys = JSONWebKeyUtil.fromJSON(contents);
        }

        SigningCommands sg = new SigningCommands(null);
        JSONWebKeys keys = sg.createJsonWebKeys();
        JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
        // While really unlikely that there would be a key collision, having one could be catastrophic
        // for users. Therefore, only add keys if there are no clashes.
        for (String x : keys.keySet()) {
            if (!sourceKeys.containsKey(x)) {
                sourceKeys.put(keys.get(x));
            }
        }
        if (hasOutputFile) {
            writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), JSONWebKeyUtil.toJSON(sourceKeys).toString(2));
        }
        say("done!");

    }

    private void addKeysHelps() {
        say("add_keys [" + CL_INPUT_FILE_FLAG + " in_file " + CL_OUTPUT_FILE_FLAG + " out_file]");
        sayi("Generates a new set of private keys and adds them to an existing key store.");
        sayi("If " + CL_INPUT_FILE_FLAG + " is specified, then that is used as the existing set, otherwise ");
        sayi("the current set of keys is used. ");
        sayi("If " + CL_OUTPUT_FILE_FLAG + " is specified, the result is written to that file.");
        say("See also, create_keys, set_keys");
    }


    public void create_keys(InputLine inputLine) throws Exception {
        // Intercept the help request here since the one in the signing utility is a bit different.
        if (showHelp(inputLine)) {
            createKeysHelps();
            return;
        }
        // Fingers and toes cases
        // #1 no arguments, create the keys and dump to std out
        if (!inputLine.hasArgs()) {
            SigningCommands sg = new SigningCommands(null);
            sg.setBatchMode(isBatchMode());
            sg.create(inputLine);
            return;
        }
        // #2 Error case that public keys are wanted, but no input file is specified.
        if (inputLine.hasArg(CL_IS_PUBLIC_FLAG) && !inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            if (isBatch()) {
                sayv("Error! Request for public keys but no set odf keys supplied.");
                System.exit(1);
            }
            say("Error! Request for public keys but no set odf keys supplied.");
            return;
        }
        boolean isPublic = inputLine.hasArg(CL_IS_PUBLIC_FLAG);
        boolean isPrivate = inputLine.hasArg(CL_IS_PRIVATE_FLAG);
        if (isPrivate && isPublic) {
            String err = "Error: cannot specify both private and public keys at the same time";
            if (isBatch()) {
                sayv(err);
                System.exit(1);
            }
            say(err);
            return;
        }
        boolean hasOutputFile = inputLine.hasArg(CL_OUTPUT_FILE_FLAG);
        if (!isPublic) {

            // next case is to just generate the full key set
            SigningCommands sg = new SigningCommands(null);
            JSONWebKeys keys = sg.createJsonWebKeys();
            JSONObject jwks = JSONWebKeyUtil.toJSON(keys);
            if (hasOutputFile) {
                writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), jwks.toString(2));
            } else {
                say(jwks.toString(2));
            }
            return;
        }
        // final case, generate the public keys.
        String contents = readFile(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));

        JSONWebKeys keys = JSONWebKeyUtil.fromJSON(contents);
        JSONWebKeys targetKeys = JSONWebKeyUtil.makePublic(keys);
        JSONObject zzz = JSONWebKeyUtil.toJSON(targetKeys);
        if (hasOutputFile) {
            writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), zzz.toString(2));
        } else {
            say(zzz.toString(2));
        }
        return;


    }

    protected void showSymmetricKeyHelp(SigningCommands signingCommands) {
        say("create_symmetric_keys [" + signingCommands.SYMMETRIC_KEY_ARG + " len + | " +
                signingCommands.SYMMETRIC_KEY_COUNT_ARG + " count | " + signingCommands.SYMMETRIC_KEY_FILE_ARG +
                " fileName] ");
        sayi("This will create a key for use as a symmetric key, i.e., this will produce");
        sayi("a base 64 encoded sequence of random bytes to be used as a symmetric key for");
        sayi("the given length. If no length is included, the default of " +
                signingCommands.defaultSymmetricKeyLength + " bytes is used.");
        sayi("If the " + signingCommands.SYMMETRIC_KEY_COUNT_ARG + " is given, this will produce that many keys");
        sayi("If the " + signingCommands.SYMMETRIC_KEY_FILE_ARG + " is given, this will write the keys to the given file, one per line.");

    }

    public void create_symmetric_keys(InputLine inputLine) {
        SigningCommands signingCommands = new SigningCommands(null);

        if (showHelp(inputLine)) {
            showSymmetricKeyHelp(signingCommands);
            return;
        }
        signingCommands.create_symmetric_keys(inputLine);
    }

    JSONWebKeys keys = null;

    String wellKnown = null;

    public void print_well_known(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printWellKnownHelp();
            return;
        }
        if (wellKnown == null || wellKnown.isEmpty()) {
            say("(not set)");
            return;
        }
        say("well known URL=\"" + wellKnown + "\"");
    }

    protected void printWellKnownHelp() {
        say("print_well_known: Prints the well-known URL that has been set.");
        sayi("Note that you set it in the set_keys call if you supply its URL");
        sayi("The well-known URL resides on a server and has the public keys listed");
        sayi("While you can validate a signature against it, you cannot create one since");
        sayi("the private key is never available through the well-knwon file.");
        say("Related: set_keys, validate_token");
    }


    protected void setKeysHelp() {
        say("set_keys: [" + CL_INPUT_FILE_FLAG + " filename | " + CL_WELL_KNOWN_FLAG + " uri]");
        sayi("Set the keys used for signing and validation in this session.");
        sayi("Either supplied a fully qualified path to the file or a uri. If you pass nothing");
        sayi("you will be prompted for a file. You can invoke this at any to change the keys.");
        say("See also: create_keys, set_default_id");
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
        File f = null;
        if (inputLine.size() == 1) {
            boolean getFile = getBooleanInput("Did you want to enter a file name?");
            if (getFile) {
                String fileName = getInput("Enter file name");
                f = new File(fileName);
            } else {
                return;
            }
        }
        if (inputLine.hasArg(CL_INPUT_FILE_FLAG)) {

            f = new File(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
            if (!f.exists()) {
                say("Sorry, the file you specified, \"" + (inputLine.getArg(1)) + "\" does not exist.");
                return;
            }
        }
        if (f != null) {
            // got a file from some place. Rock on.
            keys = readKeys(f);
            if (defaultKeyID != null) {
                if (keys.containsKey(defaultKeyID)) {
                    keys.setDefaultKeyID(defaultKeyID);
                }
            }
        } else {
            wellKnown = inputLine.getNextArgFor(CL_WELL_KNOWN_FLAG);
            try {
                keys = JWTUtil.getJsonWebKeys(new ServiceClient(URI.create("https://cilogon.org")), wellKnown);
            } catch (Throwable t) {
                sayi("Sorry, could not parse the url: \"" + t.getMessage() + "\"");
                //throw t;
            }
        }
    }


    protected JSONWebKeys readKeys(File file) throws Exception {
        return JSONWebKeyUtil.fromJSON(file);
    }


    protected void listKeysHelp() {
        say("list_keys [" + showAllKeys + " " + CL_INPUT_FILE_FLAG + " file]:This will list all the public keys " +
                "in the key file in pem format.");
        sayi("Each key will be preceeded by its unique ID in the key file.");
        sayi("You may invoke this with no argument, in which case the default key file");
        sayi("as set in the set_keys command will be used, or you can supply a fully qualified");
        sayi("path to a JSON web key file that will be used.");
        sayi("If you supply the " + showAllKeys + " flag then the private key in PKCS 8 format will be shown");
        sayi("too. Note the default is to not show the private key.");
        say("  Related: set_keys, create_keys, print_public_keys (prints in JSON format)");
    }

    protected String showAllKeys = "-showAll";

    protected void printPublicKeysHelp() {
        say("print_public_keys [file]: This will print the public keys only for a key set.");
        sayi("Note that if no file is supplied the current key set is used.");
        sayi("The result is JSON formatted. If you need PEM format use list_keys instead.");
    }

    /**
     * Prints the public keys in JSON format.
     *
     * @param inputLine
     */
    public void print_public_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printPublicKeysHelp();
            return;
        }
        JSONWebKeys localKeys = null;
        if (inputLine.hasArgs()) {
            File publicKeyFile = new File(inputLine.getLastArg());
            localKeys = readKeys(publicKeyFile);

        } else {
            localKeys = keys;
        }
        JSONWebKeys targetKeys = JSONWebKeyUtil.makePublic(localKeys);
        JSONObject zzz = JSONWebKeyUtil.toJSON(targetKeys);
        say(zzz.toString(2));
    }

    public String BASE64_FLAG = "-b64";

    protected void createPublicKeysHelp() {
        say("create_public_keys [" + BASE64_FLAG + "] [" + CL_INPUT_FILE_FLAG + " in_file] [" + CL_OUTPUT_FILE_FLAG + " out_file]");
        sayi("Take a set of private keys and extract the public keys.");
        sayi("If there is no input file, the current set of keys is used.");
        sayi("If the " + CL_OUTPUT_FILE_FLAG + " switch is given, the result will be written to the file.");
        sayi("If there is no output file specified, then the keys are printed at the console.");
        sayi("If the " + BASE64_FLAG + " flag is used, then the entire contents is base 64 encoded before");
        sayi("being displayed or written to the file.");
        say("See also: create_keys, base64");


    }

    public void create_public_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            createPublicKeysHelp();
            return;
        }
        boolean hasInputFile = inputLine.hasArg(CL_INPUT_FILE_FLAG);
        boolean hasOutputFile = inputLine.hasArg(CL_OUTPUT_FILE_FLAG);
        boolean doB64 = inputLine.hasArg(BASE64_FLAG);


        JSONWebKeys localKeys = null;
        if (hasInputFile) {
            File publicKeyFile = new File(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
            localKeys = readKeys(publicKeyFile);

        } else {
            if (keys == null) {
                say("Sorry, there is no set of active keys and no input file was specified. Exiting....");
                return;
            }
            localKeys = keys;
        }

        JSONWebKeys targetKeys = JSONWebKeyUtil.makePublic(localKeys);
        JSONObject zzz = JSONWebKeyUtil.toJSON(targetKeys);
        String finalOutput = zzz.toString(2);
        if (doB64) {
            finalOutput = Base64.encodeBase64String(finalOutput.getBytes());
        }
        if (hasOutputFile) {
            try {
                FileUtil.writeStringToFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), finalOutput);
            } catch (Throwable iox) {
                say("uh-oh... Could not write to the output file:" + iox.getMessage());
            }
        } else {
            say(finalOutput);
        }
    }

    /**
     * Write the contents of a file as a string.
     *
     * @param filename
     * @param contents
     * @throws Exception
     */
    protected void writeFile(String filename, String contents) throws Exception {
        File f = new File(filename);
        FileWriter fileWriter = new FileWriter(f);
        fileWriter.write(contents);
        fileWriter.flush();
        fileWriter.close();
    }


    public void list_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            listKeysHelp();
            return;
        }
        boolean showPrivateKeys = inputLine.hasArg(showAllKeys);
            boolean hasInputFile = inputLine.hasArg(CL_INPUT_FILE_FLAG);
        JSONWebKeys localKeys = null;
        if (showPrivateKeys && !hasInputFile) {
            // try to use the defined keys
            if (keys == null || keys.isEmpty()) {
                say("Sorry, there are no keys specified. Either use set_keys or specify a key file.");
                return;
            }
            localKeys = keys;
        } else {
            File publicKeyFile = new File(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
            localKeys = readKeys(publicKeyFile);
        }
        boolean hasDefault = localKeys.hasDefaultKey();
        String defaultKey = null;
        if (hasDefault) {
            defaultKey = localKeys.getDefaultKeyID();
        }
      boolean isFirst = true;
        for (String key : localKeys.keySet()) {
            if(isFirst){
                isFirst = false;
            }else{
                say(""); // blank line between keys.
            }
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
            if (showPrivateKeys) {
                say(KeyUtil.toPKCS8PEM(localKeys.get(key).privateKey));
            }
        }

    }


    protected void printCreateClaimsHelp() {
        say("create_claims: Prompt the user for key/value pairs and build a claims object. ");
        sayi("This will write the object to a file for future use.");
        sayi("Note: You may input JSON objects as values as well. There are various");
        sayi("places (such as creating a token) that requires a set of claims. This command");
        sayi("lets you create one.");
        say("See also: create_token, parse_claims");
    }

    /**
     * Create a set of claims and write them to a file in JSON format.
     *
     * @param inputLine
     * @throws Exception
     */
    public void create_claims(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printCreateClaimsHelp();
            return;
        }
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
            try {
                // try JSON first
                JSON json = JSONObject.fromObject(value);
                jsonObject.put(key, json);
            } catch (Throwable t) {
                // plan B. Did they give us a comma separated list we are to parse?
                if (0 < value.indexOf(",")) {
                    StringTokenizer st = new StringTokenizer(value, ",");
                    JSONArray array = new JSONArray();
                    while (st.hasMoreTokens()) {
                        array.add(st.nextToken());
                    }
                    jsonObject.put(key, array);
                } else {
                    // ok, nothing works, it's just a string...
                    jsonObject.put(key, value);

                }
            }
        }
        sayi("Here's what you inputted");
        say(jsonObject.toString(2));
        boolean isWrite = getBooleanInput("Would you like to write this to a file?[y/n]");
        //Boolean isWrite = Boolean.parseBoolean(writeToFile);
        if (isWrite) {
            String fileName = getInput("Enter filename");
            File f = new File(fileName);
            if (f.exists()) {
                String overwrite = getInput("This file exists. Do you want to overwrite it?", "false");
                if (!Boolean.parseBoolean(overwrite)) {
                    return;
                }
            }
            String output = jsonObject.toString(2);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(output.getBytes());
            fos.flush();
            fos.close();
            sayi(f + " written!");
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
        sayi("If this is not set, you will be prompted each time for an id.");
        sayi("Remember that a set of web keys does not have a default. If you import.");
        sayi("a set, you should set one as default.");
        say("See also: print_default_id");
    }

    public void set_default_id(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printSetDefaultIDHelp();
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

    protected void printPrintDefaultIDHelp() {
        say("print_default_id: This will print the current default key id that is to be used for all signing and verification.");
        say("See also: set_default_id");
    }

    public void print_default_id(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printSetDefaultIDHelp();
            return;
        }
        if (defaultKeyID == null || defaultKeyID.isEmpty()) {
            say("(not set)");
            return;
        }
        say("default key id=\"" + defaultKeyID + "\"");
    }

    protected void printParseClaimsHelp() {
        say("parse_claims [" + CL_INPUT_FILE_FLAG + " filename]");
        sayi("Read a file and print out if it parses as JSON.");
        sayi("If the filename is omitted, you will be prompted for it.");
        sayi("Note that this will try to give some limited feedback in syntax errors.");
        sayi("The intent is that if you have written a file with claims, this lets you");
        sayi("validate the JSON before using it.");
        say("See also: create_claims");
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
        boolean hasInputFile = inputLine.hasArg(CL_INPUT_FILE_FLAG);
        String filename = null;
        if (hasInputFile) {
            filename = inputLine.getNextArgFor(CL_INPUT_FILE_FLAG);
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
        return inputLine.getNextArgFor(key);
    }

    // CL = command line flags. Once upon a time, but I decided to standardize the command line flags here.
    protected String CL_KEY_FILE_FLAG = "-keys";
    protected String CL_KEY_ID_FLAG = "-key_id";
    protected String CL_WELL_KNOWN_FLAG = "-key_id";
    protected String CL_IS_PUBLIC_FLAG = "-public";
    protected String CL_IS_PRIVATE_FLAG = "-private";

    protected void createTokenHelp() {
        say("create_token " + CL_INPUT_FILE_FLAG + " claims " +
                "[" + CL_KEY_FILE_FLAG + " keyfile " + CL_KEY_ID_FLAG + " id " + CL_OUTPUT_FILE_FLAG + " outputFile]");
        sayi("Interactive mode:                                                                     ");
        sayi("   This will take the current keys (uses default) and a file containing a JSON");
        sayi("   format set of claims. It will then sign the claims with the right headers etc.");
        sayi("   and optionally print out the resulting JWT to the console. Any of the arguments omitted ");
        sayi("   will cause you to be prompted. NOTE that this only signs the token! If you need to generate");
        sayi("   accounting information like the timestamps, please use generate_token instead");
        sayi("   If you have already set the key and keyid these will be used.");
        sayi("   If the output file is given, the token will be written there instead.");
        sayi("");
        sayi("Batch mode:");
        sayi("   Creates a token from a set of claims, then signs it using the key with the given id.            ");
        sayi("   Writes the output to either the target file or prints it at the command line if no output       ");
        sayi("   file is specified.                                                                              ");
        sayi("   E.g.                                                                                            ");
        sayi("   create_token " + CL_KEY_FILE_FLAG + " keys.jwk " + CL_KEY_ID_FLAG + " ABC123 " + CL_INPUT_FILE_FLAG +
                " my_claims.txt " + CL_OUTPUT_FILE_FLAG + " my_token.jwt");
        sayi("  Will read the keys in the file keys.jwk, select the one with id ABC123 then                   ");
        sayi("  read in the my_claims.txt file (assumed to be a set of claims in JSON format)                 ");
        sayi("  and create the header and signature. It will then place the result into the file my_token.jwt ");
        sayi("                                                                                                ");
        sayi("create_token " + CL_WELL_KNOWN_FLAG + " https://fnord.baz/.well-known " + CL_KEY_ID_FLAG +
                " CAFEBEEF " + CL_INPUT_FILE_FLAG + " my_claims.txt           ");
        sayi("This will read the well-known file, parse it for the keys, load the keys, find the key       ");
        sayi("with id CAFEBEEF read in the claims file then print the resulting token to the command line. ");
        say("Related: generate_token, set_keys, set_default_id, print_token, verify_token");
    }

    String lastToken = null;

    public void create_token(InputLine inputLine) throws Exception {

        if (showHelp(inputLine)) {
            createTokenHelp();
            return;
        }
        // pull off the command line arguments
        File outputFile = null;
        if (inputLine.hasArg(CL_OUTPUT_FILE_FLAG)) {
            outputFile = new File(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG));
        }

        JSONWebKeys localKeys = null;
        if (inputLine.hasArg(CL_KEY_FILE_FLAG)) {
            String fileName = getArgValue(inputLine, CL_KEY_FILE_FLAG);
            File f = new File(fileName);
            if (!f.exists()) {
                say("Sorry, that file does not seem to exist");
                return;
            }
            if (!f.isFile()) {
                say("Sorry, the thing you specified is not a file.");
                return;
            }
            localKeys = readKeys(f);
        }
        if (inputLine.hasArg(CL_WELL_KNOWN_FLAG)) {
            localKeys = getJsonWebKeys(inputLine.getNextArgFor(CL_WELL_KNOWN_FLAG));

        }
        if (localKeys == null) {
            if (isBatchMode()) {
                // Error in this case -- there cannot be a set of keys defined, so exit
                sayv("Error: no keys specified");
                return;
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
        }
        String localDefaultID = null;
        if (inputLine.hasArg(CL_KEY_ID_FLAG)) {
            localDefaultID = getArgValue(inputLine, CL_KEY_ID_FLAG);
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
        if (inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            claims = JSONObject.fromObject(readFile(getArgValue(inputLine, CL_INPUT_FILE_FLAG)));
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
        if (outputFile == null) {
            say(signedToken);
        } else {
            FileWriter fileWriter = new FileWriter(outputFile);
            fileWriter.write(signedToken);
            fileWriter.flush();
            fileWriter.close();
        }
    }

    protected void generateTokenHelp() {
        say("generate_token " +
                CL_INPUT_FILE_FLAG + "  claims " +
                CL_KEY_FILE_FLAG + " keyFile " +
                CL_KEY_ID_FLAG + " keyId " +
                "[" + JTI_FLAG + " | " +
                PRINT_CLAIMS_FLAG + " | " +
                LIFETIME_FLAG + "  lifetime | " +
                CL_OUTPUT_FILE_FLAG + " outFile]");
        sayi("Generate a token from the claims. This includes adding in the current time and using the lifetime (if given)");
        sayi("to create the token. A JTI will also be created. ");
        sayi("The meaning of the various optional flags is as follows");
        sayi(CL_INPUT_FILE_FLAG + " (required) The text file of a JSON object that has the claims.");
        sayi(CL_KEY_FILE_FLAG + " (required) + The JWK format file containing the keys. This must contain a private key.");
        sayi(CL_KEY_ID_FLAG + " (required) The id in the key file of the key to use.");
        sayi(JTI_FLAG + " (optional) If specified, generate a unique identifier for this id token. You may also just");
        sayi("    put one in the claims file if you need it immutable.");
        sayi(PRINT_CLAIMS_FLAG + " (optional) If specified, this will print out the generated claims (not token!) to the command line.");
        sayi(LIFETIME_FLAG + " (optional) Specifies the lifetime in seconds for this token. The default is " + DEFAULT_LIFETIME + " seconds.");
        sayi("    Note: not specifying an output file will print the resulting token.");
        sayi(CL_OUTPUT_FILE_FLAG + " (optional) The file to which the resulting token is written. Omitting this dumps it to the command line.");
    }


    protected String LIFETIME_FLAG = "-lifetime";
    protected String JTI_FLAG = "-jti";
    protected String PRINT_CLAIMS_FLAG = "-print_claims";
    protected long DEFAULT_LIFETIME = 600; // in seconds.
    /*
    This next constant takes a wee bit of explaining. We create a big int and then want to use it as an identifier.
    We also want to avoid collisions, so a rather long sequence of random bytes is good. Rather than just pass along
    a big integer, we could encode it with a radix of 16 (turning it into a hex number) or in this case, use a radix of
    36 which uses all 26 letters of the alphabet and digits. This makes it much more compact.
    If you really need to, you reconstruct this with the (String,int) constructor for BigInteger.
    (Being a Math guy this just seemed natural, but I decided to stick a note here to explain it.)
     */
    protected int JTI_RADIX = 36;

    public void generate_token(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            generateTokenHelp();
            return;
        }
        if (gracefulExit(!inputLine.hasArg(CL_INPUT_FILE_FLAG), "Missing claims file.")) return;
        if (gracefulExit(!inputLine.hasArg(CL_KEY_FILE_FLAG), "Missing keys file.")) return;
        if (gracefulExit(!inputLine.hasArg(CL_KEY_ID_FLAG), "Missing key id for signature.")) return;

        String localDefaultID = getArgValue(inputLine, CL_KEY_ID_FLAG);
        JSONWebKeys localKeys = readKeys(new File(inputLine.getNextArgFor(CL_KEY_FILE_FLAG)));
        if (gracefulExit(!localKeys.containsKey(localDefaultID), "The key id is not in the key set. Check the id."))
            return;

        long lifetime = DEFAULT_LIFETIME;

        if (inputLine.hasArg(LIFETIME_FLAG)) {
            lifetime = Long.parseLong(inputLine.getNextArgFor(LIFETIME_FLAG));
        }
        long issuedAt = new Date().getTime(); // in milliseconds. Eventually this turns into seconds.

        JSONObject claims = readJSON(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
        // now we set the claims.

        claims.put(OA2Claims.ISSUED_AT, issuedAt / 1000);
        claims.put(OA2Claims.NOT_VALID_BEFORE, issuedAt / 1000);
        //  claims.put(OA2Claims.AUTH_TIME, issuedAt/1000);
        claims.put(OA2Claims.EXPIRATION, (issuedAt / 1000) + lifetime);
        if (inputLine.hasArg(JTI_FLAG)) {
            // A JTI flag means create a random JTI. Otherwise, the user should just stick it in the file..
            String jti = "";
            SecureRandom secureRandom = new SecureRandom();
            byte[] secret = new byte[32];
            secureRandom.nextBytes(secret);
            BigInteger bigInteger = new BigInteger(secret);
            bigInteger = bigInteger.abs(); // so no signs in final output

            jti = "jti://" + bigInteger.toString(JTI_RADIX);// default is lower case. Note this has 0 (zero) and o (letter "oh")!
            claims.put(OA2Claims.JWT_ID, jti);
        }
        if (inputLine.hasArg(PRINT_CLAIMS_FLAG)) {
            say(claims.toString(2));
        }
        String signedToken = JWTUtil.createJWT(claims, localKeys.get(localDefaultID));
        if (inputLine.hasArg(CL_OUTPUT_FILE_FLAG)) {
            writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), signedToken);
        } else {
            say(signedToken);
        }
    }


    protected void printTokenHelp() {
        say("print_token: [" + CL_INPUT_FILE_FLAG + " file | token] Print the given token's header and payload, doing no verification.");
        sayi("Interactive mode:");
        sayi("    If you omit the argument, it will print the last token generated by the create_token call.");
        sayi("    If there is no last token, that will be shown too. ");
        sayi("Batch mode:");
        sayi("    Print the token specified by the file or given at the command line.");
        say("Related: create_token");
    }

    public void print_token(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printTokenHelp();
            return;
        }
        if (inputLine.isEmpty()) {
            if (lastToken == null) {
                say("(no token has been created)");
                return;
            }
            say(lastToken);
            return;
        }
        String rawToken = null;
        if (inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            rawToken = readFile(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
        } else {
            rawToken = inputLine.getLastArg();
        }
        JSONObject[] payloads = JWTUtil.readJWT(rawToken);
        say("header");
        say(payloads[JWTUtil.HEADER_INDEX].toString(2));
        say("payload");
        say(payloads[JWTUtil.PAYLOAD_INDEX].toString(2));

    }

    protected void printListKeyIDs() {
        say("list_key_ids [filename]");
        sayi("List the unique key ids in the file");
        sayi("If you do not supply an argument, the globally set keys will be used");
        sayi("If there is no default set of keys, you will be prompted for a file");
        say("See also: set_keys, set_default_id");
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
        say("validate_token [" + CL_WELL_KNOWN_FLAG + " url | " + CL_KEY_FILE_FLAG + " file " + CL_INPUT_FILE_FLAG + " filename  | token]");
        sayi("Interactive mode:                                                                                                            ");
        sayi("    This will take a token and check the signature. It will also print out the payload");
        sayi("    and header information.");
        sayi("    The validation is against the current set of keys or against a URL specified with the");
        sayi("    -wellKnown flag. You can also point to a key file (file with JSON web keys in it) with");
        sayi("    the -keyFile flag.");
        sayi("    You may supply either the token itself or specify with the -file flag that this is in a file.");
        sayi(" Batch mode:");
        sayi("    This will verify a given jwt given either a set of keys or a well-known url (from which the key will            ");
        sayi("    be extracted. You may either specify the token in a file or as the final argument.                              ");
        sayi("    This will result in a return code of 1 if the token is valid or 0 if not.                                       ");
        sayi("    E.g.s                                                                                                          ");
        sayi("    validate_token " + CL_WELL_KNOWN_FLAG + " https://foo.bar/.well-known " + CL_INPUT_FILE_FLAG + " my_token.jwt                                         ");
        sayi("       This will read the keys in the well-known file and read the token in the file                                ");
        sayi("                                                                                                                 ");
        sayi("    validate_token " + CL_WELL_KNOWN_FLAG + "https://foo.bar/.well-known -v " + CL_INPUT_FILE_FLAG + " my_token.jwt                                      ");
        sayi("       Identical behavior to the first example but note the -v flag: This causes any information about              ");
        sayi("       the token to be printed. Normally this is not used except for trying to debug issues.                        ");
        sayi("                                        ");
        sayi("    validate_token " + CL_KEY_FILE_FLAG + "  keys.jwk eyJ...........                                                                    ");
        sayi("       This will read in the keys from the give file and the assumption is that the last argument is the token itself");
        sayi("       Note that in this example the token is truncated so it fits here.                                     ");
        say("See also: create_token");
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
        if (inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            token = inputLine.getNextArgFor(CL_INPUT_FILE_FLAG);
        } else {
            token = inputLine.getLastArg();
        }
        JSONWebKeys keys = this.keys;
        if (inputLine.hasArg(CL_WELL_KNOWN_FLAG)) {
            String wellKnown = inputLine.getNextArgFor(CL_WELL_KNOWN_FLAG);
            try {
                // Actually we don't use the uri below, but one is needed to create the class
                keys = JWTUtil.getJsonWebKeys(new ServiceClient(URI.create("https://cilogon.org")), wellKnown);
            } catch (Throwable t) {
                sayi("Sorry, could not parse the url: \"" + wellKnown + "\". Message=\"" + t.getMessage() + "\"");
            }
        }
        if (inputLine.hasArg(CL_KEY_FILE_FLAG) && !inputLine.hasArg(CL_WELL_KNOWN_FLAG)) { // only take one if both are specified and well known is preferred
            File f = new File(inputLine.getNextArgFor(CL_KEY_FILE_FLAG));

            if (gracefulExit(!f.exists(), "Sorry, the file \" + f + \" does not exist")) return;

            try {
                keys = readKeys(f);
            } catch (Throwable t) {
                if (gracefulExit(true, "Sorry, could not load the file: \"" +
                        inputLine.getNextArgFor("-keyFile") + "\". Message=\"" + t.getMessage() + "\"")) return;
            }
        }
        if (gracefulExit(keys == null, "Sorry, no keys set, please set keys or specify a well-known URL.")) return;

        String[] x = decat(token);
        JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[0])));
        JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[1])));
        if (JWTUtil.verify(h, p, x[2], keys.get(h.getString("kid")))) {
            if (isBatch()) {
                sayv("token valid!");
                return;
            }
            say("token valid!");
        } else {
            if (isBatch()) {
                sayv("could not validate token");
                System.exit(1);
            }
            say("could not validate token");
        }
    }

    public void error(Throwable t, String message) {
        if (logger != null) {
            logger.error(message, t);
        }
    }

    public static void main(String[] args) {
        try {
            String sig = "L2ZN8jp_-SmPmAiEels5DsGKx-nh--EPo3lgGTqp6Kpp5IpwKrgpK0Wc34Cs2iALYtQqyaqvrWVhr1kZxS9_TI4WrE84BIYlpuFc-hSqKl4JVRHhn0ij_Jg7_Y6KuwPdfKeWNq6L9wUxKJPyIMU3WxGV-Nrcl9nAYt9SlrqMBOA7bARuUQfl1maZ05HRZFImL0Ol1PbAOfnbff74P323dbwzGJ1AxqQIvfVmniJXwr_4K88yZxrcYTs81yse8oT1SAsTffiVKJvwoD4DctMxkYas-_mJPaW-WNylBME8GR-R3f0RjTxJ-xO5WlMP8kbVJ2V5rcdzjirqIWqfF9i1Eg";
            byte[] byetArray = Base64.decodeBase64(sig);
            String path = "/home/ncsa/temp/rokwire/sig.b";
            File f = new File(path);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(byetArray, 0, byetArray.length);
            FileOutputStream fileOutputStream = new FileOutputStream(f);
            baos.writeTo(fileOutputStream);
            fileOutputStream.flush();
            fileOutputStream.close();
        } catch (Throwable t) {
            t.printStackTrace();
        }


    }

    String base64Encode = "-encode";
    String base64Dencode = "-decode";
    String base64Bytes = "-binary";

    protected void base64Help() {
        say("base64 " + base64Encode + " | " + base64Dencode + " " + base64Bytes + " " + CL_INPUT_FILE_FLAG + " in_file " + CL_OUTPUT_FILE_FLAG + " out_file | arg");
        sayi("This will encode or decode a base 64 arg. ");
        sayi("You may specify which input or output. If none is given, then the assumption is that the input is the arg");
        sayi("and the output is to the terminal.");
        sayi(base64Dencode + ": the input is base64 encoded, output is plain text");
        sayi(base64Encode + ": the input is plain text, output is base 64 encoded.");
        sayi(base64Bytes + " treat the output as bytes. Generally this implies you have specified an output file.");
        sayi("Note: i the output is binary, you should specify a file as the target since otherwise you get gibbersih.");
    }

    public void base64(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            base64Help();
            return;
        }
        boolean hasInfile = inputLine.hasArg(CL_INPUT_FILE_FLAG);
        boolean hasOutfile = inputLine.hasArg(CL_OUTPUT_FILE_FLAG);
        boolean isEncode = inputLine.hasArg(base64Encode);
        boolean isDecode = inputLine.hasArg(base64Dencode);
        boolean isBinary = inputLine.hasArg(base64Bytes);
        gracefulExit(isDecode && isEncode, "Sorry, you cannot specify both encoding and decoding at the same time");

        String input = "";
        if (hasInfile) {
            input = readFile(inputLine.getNextArgFor(CL_INPUT_FILE_FLAG));
        } else {
            input = inputLine.getLastArg();
        }
        String output = "";
        if (isEncode) {
            output = Base64.encodeBase64String(input.getBytes());
            if (hasOutfile) {
                writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), output);
            } else {
                say(output);
            }
            return;
        } else {
            // decoding to bytes
            byte[] bytes = Base64.decodeBase64(input);
            if (!hasOutfile) {
                say(new String(bytes));
                return;
            }

            if (isBinary) {
                File f = new File(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG));
                FileOutputStream fos = new FileOutputStream(f);
                fos.write(bytes);
                fos.flush();
                fos.close();
            } else {
                writeFile(inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG), new String(bytes));
                return;
            }
        }
    }
}
