package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
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

import java.io.*;
import java.net.URI;
import java.util.StringTokenizer;

import static edu.uiuc.ncsa.security.oauth_2_0.JWTUtil.decat;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/6/19 at  2:39 PM
 */
public class JWKUtilCommands extends CommonCommands {
    // TODO: Move batch file and all other functionality here up to CommonCommands!  Be sure to update SciTokensUtil accordingly since it uses it.

      /**
       * If this is used, then each line of the file is read as an input and processed. It overrides the
       * {@link #BATCH_MODE_FLAG} if used and that is ignored.
       */
      public static String BATCH_FILE_MODE_FLAG = "-batchFile";
      /**
       * If a line contains this character, then the line is truncated at that point before processing.
       */
      //public static String BATCH_FILE_COMMENT_CHAR = "//";
      /**
       * If a line ends with this (after the comment is removed), then glow it on to the
       * next input line. In effect this lets you split commands across multiple lines, e.g.
       * <pre>
       * ls \//My comment
       * -la \
       * foobar
       * </pre>
       * is the same as entering the single line
       * <pre>ls -la foobar</pre>
       * Notice that the lines are concatenated and the comment is stripped out.
       */
      public static String BATCH_FILE_LINE_CONTINUES = "\\";

      public boolean isBatchFile() {
          return batchFile;
      }

      public void setBatchFile(boolean batchFile) {
          this.batchFile = batchFile;
      }

      protected boolean batchFile = false;

      public boolean isVerbose() {
          return verbose;
      }

      /**
       * So batch files can change whether or not they are verbose
       *
       * @param inputLine
       */
      public void set_verbose(InputLine inputLine) throws Exception {
          if (inputLine.hasArg("true")) {
              setVerbose(true);
          } else {
              setVerbose(false);
          }
      }

      public void set_no_output(InputLine inputLine) throws Exception {
          // A little bit trickier than it looks since we have an internal flag for the negation of this.
          // We also want to be sure they really want to turn off output, so we only test for logical true
          // That way if they screw it up they still at least get output...
          if (inputLine.hasArg("true")) {
              setPrintOuput(false);
          } else {
              setPrintOuput(true);
          }
      }


      public void setVerbose(boolean verbose) {
          this.verbose = verbose;
      }

      boolean verbose;

      /**
       * If this is set true, then no output is generated. This is usedul in batch mode or with a batch file.
       *
       * @return
       */
      public boolean isPrintOuput() {
          return printOuput;
      }

      public void setPrintOuput(boolean printOuput) {
          this.printOuput = printOuput;
      }

      boolean printOuput = true; // default is to always print output since this a command line tool.
      // END OF Batch File processing stuff.

      public JWKUtilCommands(MyLoggingFacade logger) {
          super(logger);
      }

      @Override
      public String getPrompt() {
          return "jwks>";
      }

      public static String JWK_EXTENSION = "jwk";

      public void create_keys(InputLine inputLine) throws Exception {
          SigningCommands sg = new SigningCommands(null);
          sg.setBatchMode(isBatchMode());
          sg.create(inputLine);
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
          say("set_keys: [-file filename | uri]");
          say("          Set the keys used for signing and validation in this session.");
          say("          Either supplied a fully qualified path to the file or a uri. If you pass nothing");
          say("          yo will be prompted for a file. You can invoke this at any to change the keys.");
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
          if (inputLine.hasArg("-file")) {

              f = new File(inputLine.getArg(2));
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
              wellKnown = inputLine.getArg(1);
              try {
                  keys = JWTUtil.getJsonWebKeys(new ServiceClient(URI.create("https://scitokens.org")), wellKnown);
              } catch (Throwable t) {
                  sayi("Sorry, could not parse the url: \"" + t.getMessage() + "\"");
                  //throw t;
              }
          }
      }


      protected JSONWebKeys readKeys(File file) throws Exception {
          return JSONWebKeyUtil.fromJSON(file);
      }

      @Override
      protected void say(String x) {
          if (isPrintOuput()) {
              super.say(x);
          }
      }

      /**
       * Use this for verbose mode.
       *
       * @param x
       */
      protected void vSay(String x) {
          // suppress output if this is run from the command line.
          if (isPrintOuput() && isVerbose()) {
              super.say(x);
          }
      }

      protected void versionHelp() {
          sayi("version - prints the current version number of this program.");
      }

      public void version(InputLine inputLine) {
          if (showHelp(inputLine)) {
              versionHelp();
              return;
          }
          say("* SciTokens CLI (Command Line Interpreter) Version " + LoggingConfigLoader.VERSION_NUMBER);
      }

      protected void listKeysHelp() {
          say("list_keys [file]:This will list all the public keys in the key file in pem format.");
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

      protected void createTokenHelp() {
          say("create_token -file claims [-keys keyfile -keyid id -out outputFile]");
          say("              This will take the current keys (uses default) and a file containing a JSON");
          say("              format set of claims. It will then sign the claims with the right headers etc.");
          say("              and optionally print out the resulting JWT to the console. Any of the arguments omitted will cause you");
          say("              to be prompted. If you have already set the key and keyid these will be used.");
          say("              If the output file is given, the token will be written there instead.");
          say("Related: set_keys, set_default_id, print_token");
      }

      String lastToken = null;

      public void create_token(InputLine inputLine) throws Exception {
          if (showHelp(inputLine)) {
              createTokenHelp();
              return;
          }
          // pull off the command line arguments
          File outputFile = null;
          if(inputLine.hasArg("-outputFile")){
              outputFile = new File(inputLine.getNextArgFor("-outputFile"));
          }

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
          if(outputFile == null) {
              say(signedToken);
          }else{
              FileWriter fileWriter = new FileWriter(outputFile);
              fileWriter.write(signedToken);
              fileWriter.flush();
              fileWriter.close();
          }
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
          say("validate_token [-wellKnown url | -keyFile file -file filename  | string]");
          say("         This will take a token and check the signature. It will also print out the payload");
          say("         and header information.");
          say("         The validation is against the current set of keys or against a URL specified with the");
          say("         -wellKnown flag. You can also point to a key file (file with JSON web keys in it) with");
          say("         the -keyFile flag.");
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
              token = inputLine.getNextArgFor("-file");
          } else {
              token = inputLine.getLastArg();
          }
          JSONWebKeys keys = this.keys;
          if (inputLine.hasArg("-wellKnown")) {
              String wellKnown = inputLine.getNextArgFor("-wellKnown");
              try {
                  keys = JWTUtil.getJsonWebKeys(new ServiceClient(URI.create("https://scitokens.org")), wellKnown);
              } catch (Throwable t) {
                  sayi("Sorry, could not parse the url: \"" + wellKnown + "\". Message=\"" +  t.getMessage() + "\"");
              }
          }
          if(inputLine.hasArg("-keyFile") && !inputLine.hasArg("-wellKnown")){ // only take one if both are specified and well known is preferred
              File f = new File(inputLine.getNextArgFor("-keyFile"));
              if(!f.exists()){
                  say("Sorry, the file " + f + " does not exist");
                  return;
              }
              try{
                  keys = readKeys(f);
              }catch(Throwable t){
                  sayi("Sorry, could not load the file: \"" + inputLine.getNextArgFor("-keyFile") + "\". Message=\"" +  t.getMessage() + "\"");
              }
          }
          if(keys == null){
              say("Sorry, no keys set, please set keys or specify a well-known URL");
              return;
          }
          String[] x = decat(token);
          JSONObject h = JSONObject.fromObject(new String(Base64.decodeBase64(x[0])));
          JSONObject p = JSONObject.fromObject(new String(Base64.decodeBase64(x[1])));
          say("header=" + h);
          say("payload=" + p);
          if (JWTUtil.verify(h, p, x[2], keys.get(h.getString("kid")))) {
              say("token valid!");
          } else {
              say("could not validate token");
          }
      }

      public void error(Throwable t, String message) {
          if (logger != null) {
              logger.error(message, t);
          }
      }
}
