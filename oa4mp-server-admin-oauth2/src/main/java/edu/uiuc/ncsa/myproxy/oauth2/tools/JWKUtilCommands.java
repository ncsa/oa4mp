package edu.uiuc.ncsa.myproxy.oauth2.tools;

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
        say("  Create a set of RSA JSON Web keys and store them in the given file");
        say("  There are several modes of operation. If you do not specify an output file, then the keys are written ");
        say("  to the command line.");
        say("  Interactive mode:");
        say("     E.g.");
        say("     create_keys " + CL_OUTPUT_FILE_FLAG + " keys.jwk");
        say("         This will create a set of key pairs with random ids and store the result in the file kwys.jwk");
        say("");
        say("     create_keys");
        say("          with no arguments, a full set of keys will be created and printed to the command line.");
        say("  Batch mode:");
        say("     ");
        say("     You can also take a set of keys and extract the set of public keys. Various JWT toolkits require this.");
        say("     create_keys " + CL_IS_PUBLIC_FLAG + " " + CL_INPUT_FILE_FLAG + " keys.jwk " + CL_OUTPUT_FILE_FLAG + "  pub_keys.jwk");
        say("          This will take the full set of keys in keys.jwk extract the public keys and place the result in pub_keys.jwk");
        say("          Note: including the -public flag implies the -in argument is given and an error will result if it is not found");
        say("See also create_public_keys");
    }




    public void create_keys(InputLine inputLine) throws Exception {
        // Intercept the help request here since the one in the signing utility is a bit different.
        if (showHelp(inputLine)) {
            createKeysHelps();
            return;
        }
        // Fingers and toes cases
        // #1 no arguments, create the keys and dump to st out
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
        say("                  Note that you set it in the set_keys call if you supply its URL");
        say("                  The well-known URL resides on a server and has the public keys listed");
        say("                  While you can validate a signature against it, you cannot create one since");
        say("                  the private key is never available through the well-knwon file.");
        say("Related: set_keys, validate_token");
    }


    protected void setKeysHelp() {
        say("set_keys: [" + CL_INPUT_FILE_FLAG + " filename | " + CL_WELL_KNOWN_FLAG + " uri]");
        say("          Set the keys used for signing and validation in this session.");
        say("          Either supplied a fully qualified path to the file or a uri. If you pass nothing");
        say("          you will be prompted for a file. You can invoke this at any to change the keys.");
        say("  Related: create_keys, set_default_id");
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
        say("list_keys [" + showAllKeys + " file]:This will list all the public keys in the key file in pem format.");
        say("           Each key will be preceeded by its unique ID in the key file.");
        say("           You may invoke this with no argument, in which case the default key file");
        say("           as set in the set_keys command will be used, or you can supply a fully qualified");
        say("           path to a JSON web key file that will be used.");
        say("           If you supply the " + showAllKeys + " flag then the private key in PKCS 8 format will be shown");
        say("           too. Note the default is to not show the private key.");
        say("  Related: set_keys, create_keys, print_public_keys (prints in JSON format)");
    }

    protected String showAllKeys = "-showAll";

    protected void printPublicKeysHelp() {
        say("print_public_keys [file]: This will print the public keys only for a key set.");
        say("                          Note that if no file is supplied the current key set is used.");
        say("                          The result is JSON formatted. If you need PEM format use list_keys instead.");
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

    public void create_public_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            printPublicKeysHelp();
            return;
        }
        JSONWebKeys localKeys = null;
        if (inputLine.hasArgs()) {
            File publicKeyFile = new File(inputLine.getArg(1));
            localKeys = readKeys(publicKeyFile);

        } else {
            localKeys = keys;
        }
        JSONWebKeys targetKeys = JSONWebKeyUtil.makePublic(localKeys);
        JSONObject zzz = JSONWebKeyUtil.toJSON(targetKeys);

        say(zzz.toString(2));

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

        JSONWebKeys localKeys = null;
        if (showPrivateKeys && 1 == inputLine.size()) {
            // try to use the defined keys
            if (keys == null || keys.isEmpty()) {
                say("Sorry, there are no keys specified. Either use setkeys or specify a key file.");
                return;
            }

            localKeys = keys;
        } else {
            File publicKeyFile = new File(inputLine.getLastArg());
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
            if (showPrivateKeys) {
                say(KeyUtil.toPKCS8PEM(localKeys.get(key).privateKey));
            }
        }

    }


    protected void printCreateClaimsHelp() {
        say("create_claims: Prompt the user for key/value pairs and build a claims object. ");
        say("               This will write the object to a file for future use.");
        say("               Note: You may input JSON objects as values as well. There are various");
        say("               places (such as creating a token) that requires a set of claims. This command");
        say("               lets you create one.");
        say("");
        say("Related: create_token, parse_claims");
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
        say("                        If this is not set, you will be prompted each time for an id.");
        say("                        Remember that a set of web keys does not have a default. If you import.");
        say("                        a set, you should set one as default.");
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
        say("Related: set_default_id");
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
        say("parse_claims [filename]");
        say("           Read a file and print out if it parses as JSON.");
        say("           If the filename is omitted, you will be prompted for it.");
        say("           Note that this will try to give some limited feedback in syntax errors.");
        say("           The intent is that if you have written a file with claims, this lets you");
        say("           validate the JSON before using it.");
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
        say("   Interactive mode:                                                                     ");
        say("      This will take the current keys (uses default) and a file containing a JSON");
        say("      format set of claims. It will then sign the claims with the right headers etc.");
        say("      and optionally print out the resulting JWT to the console. Any of the arguments omitted ");
        say("      will cause you to be prompted. NOTE that this only signs the token! If you need to generate");
        say("      accounting information like the timestamps, please use generate_token instead");
        say("      If you have already set the key and keyid these will be used.");
        say("      If the output file is given, the token will be written there instead.");
        say("");
        say("   Batch mode:");
        say("      Creates a token from a set of claims, then signs it using the key with the given id.            ");
        say("      Writes the output to either the target file or prints it at the command line if no output       ");
        say("      file is specified.                                                                              ");
        say("      E.g.                                                                                            ");
        say("      create_token " + CL_KEY_FILE_FLAG + " keys.jwk " + CL_KEY_ID_FLAG + " ABC123 " + CL_INPUT_FILE_FLAG +
                " my_claims.txt " + CL_OUTPUT_FILE_FLAG + " my_token.jwt");
        say("        Will read the keys in the file keys.jwk, select the one with id ABC123 then                   ");
        say("        read in the my_claims.txt file (assumed to be a set of claims in JSON format)                 ");
        say("        and create the header and signature. It will then place the result into the file my_token.jwt ");
        say("                                                                                                      ");
        say("      create_token " + CL_WELL_KNOWN_FLAG + " https://fnord.baz/.well-known " + CL_KEY_ID_FLAG +
                " CAFEBEEF " + CL_INPUT_FILE_FLAG + " my_claims.txt           ");
        say("         This will read the well-known file, parse it for the keys, load the keys, find the key       ");
        say("         with id CAFEBEEF read in the claims file then print the resulting token to the command line. ");
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
                LIFETIME_FLAG + "  lifetime " +
                JTI_FLAG + " " +
                PRINT_CLAIMS_FLAG + " " +
                CL_KEY_ID_FLAG + " keyId " +
                CL_OUTPUT_FILE_FLAG + " outFile");
        say("    Generate a token from the claims. This includes adding in the current time and using the lifetime (if given)");
        say("    to create the token. A JTI will also be created. ");
        say("    The meaning of the various optional flags is as follows");
        say("    " + LIFETIME_FLAG + " (optional) Specifies the lifetime in seconds for this token. The default is " + DEFAULT_LIFETIME + " seconds.");
        say("    " + JTI_FLAG + " (optional) If specified, generate a unique identifier for this id token. You may also just");
        say("         put one in the claims file if you need it immutable.");
        say("    " + PRINT_CLAIMS_FLAG + " (optional) If specified, this will print out the generated claims (not token!) to the command line.");
        say("        Note: not specifying an output file will print the resulting token.");
        say("    " + CL_INPUT_FILE_FLAG + " (required) The text file of a JSON object that has the claims.");
        say("    " + CL_KEY_FILE_FLAG + " (required) + The JWK format file containing the keys. This must contain a private key.");
        say("    " + CL_KEY_ID_FLAG + " (required) The id in the key file of the key to use.");
        say("    " + CL_OUTPUT_FILE_FLAG + " (optional) The file to which the resulting token is written. Omitting this dumps it to the command line.");
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
    (Being a Math guy this seemed natural, but I decided to stick a note here to explain it.)
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
        say("    Interactive mode:");
        say("        If you omit the argument, it will print the last token generated by the create_token call.");
        say("        If there is no last token, that will be shown too. ");
        say("    Batch mode:");
        say("        Print the token specified by the file or given at the command line.");
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
        say("validate_token [" + CL_WELL_KNOWN_FLAG + " url | " + CL_KEY_FILE_FLAG + " file " + CL_INPUT_FILE_FLAG + " filename  | token]");
        say("    Interactive mode:                                                                                                            ");
        say("         This will take a token and check the signature. It will also print out the payload");
        say("         and header information.");
        say("         The validation is against the current set of keys or against a URL specified with the");
        say("         -wellKnown flag. You can also point to a key file (file with JSON web keys in it) with");
        say("         the -keyFile flag.");
        say("         You may supply either the token itself or specify with the -file flag that this is in a file.");
        say("     Batch mode:");
        say("          This will verify a given jwt given either a set of keys or a well-known url (from which the key will            ");
        say("          be extracted. You may either specify the token in a file or as the final argument.                              ");
        say("          This will result in a return code of 1 if the token is valid or 0 if not.                                       ");
        say("          E.g.s                                                                                                          ");
        say("          validate_token " + CL_WELL_KNOWN_FLAG + " https://foo.bar/.well-known " + CL_INPUT_FILE_FLAG + " my_token.jwt                                         ");
        say("             This will read the keys in the well-known file and read the token in the file                                ");
        say("                                                                                                                       ");
        say("          validate_token " + CL_WELL_KNOWN_FLAG + "https://foo.bar/.well-known -v " + CL_INPUT_FILE_FLAG + " my_token.jwt                                      ");
        say("             Identical behavior to the first example but note the -v flag: This causes any information about              ");
        say("             the token to be printed. Normally this is not used except for trying to debug issues.                        ");
        say("                                              ");
        say("          validate_token " + CL_KEY_FILE_FLAG + "  keys.jwk eyJ...........                                                                    ");
        say("             This will read in the keys from the give file and the assumption is that the last argument is the token itself");
        say("             Note that in this example the token is truncated so it fits here.                                     ");
        say("Related: create_token");
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
        say("  This will encode or decode a base 64 arg. ");
        say("  You may specify which input or output. If none is given, then the assumption is that the input is the arg");
        say("  and the output is to the terminal.");
        say("   " + base64Dencode + ": the input is base64 encoded, output is plain text");
        say("   " + base64Encode + ": the input is plain text, output is base 64 encoded.");
        say("   " + base64Bytes + " treat the output as bytes. Generally this implies you have specified an output file.");
        say("   Note: i the output is binary, you should specify a file as the target since otherwise you get gibbersih.");
    }

    public void base64(InputLine inputLine) throws Exception {
        if(showHelp(inputLine)){
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
