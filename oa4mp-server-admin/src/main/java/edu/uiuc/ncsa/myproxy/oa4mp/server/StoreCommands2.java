package edu.uiuc.ncsa.myproxy.oa4mp.server;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigRenderOptions;
import edu.uiuc.ncsa.qdl.util.FileUtil;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DoubleHashMap;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.*;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.io.*;
import java.net.URI;
import java.util.*;

import static edu.uiuc.ncsa.security.core.util.StringUtils.*;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.CLEAR_BUFFER_COMMAND;
import static edu.uiuc.ncsa.security.util.cli.CLIDriver.EXIT_COMMAND;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization and searching
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  10:06 AM
 */
public abstract class StoreCommands2 extends StoreCommands {
    /*
     SQL Command to get non-version:
     SELECT client_id FROM clients WHERE client_id  NOT LIKE '%#version%';

     Counting non-versions:
     SELECT count(*)  FROM clients WHERE client_id  NOT LIKE '%#version%';
     */
    public static final String FILE_FLAG = "-file";
    public static final String UPDATE_FLAG = "-update";
    public static final String SHORT_UPDATE_FLAG = "-u";

    public StoreCommands2(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public StoreCommands2(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    protected void showSerializeHelp() {
        say("serializes an object and either shows it on the command line or put it in a file. Cf. deserialize.");
        say("serialize  [-file path] index");
        say("Serializes the object with the given index. (Note that the index must be the last argument!) " +
                "It will print it to the command line or save it to the given file,");
        say("overwriting the contents of the file.");
    }

    protected void showDeserializeHelp() {
        say("Deserializes an object into the currnet store overwriting the contents. Cf. serialize.");
        say("deserialize  [-new] -file path [" + SHORT_UPDATE_FLAG + "|" + UPDATE_FLAG + "]");
        say("Deserializes the object in the given file. This replaces the object with the given index in the store.");
        say("The response will give the identifier of the object created.");
        say("If the -new flag is used, it is assumed that the object should be new. This means that if there is an existing object");
        say("with that identifier the operation will fail. If there is no identifier, one will be created.");
        say("Omitting the -new flag means that any object will be overwritten and if needed, a new identifier will be created");
        say("If the  " + UPDATE_FLAG + " or " + SHORT_UPDATE_FLAG + " is used, the existing object is simply updated");
        say("Note that an object cannot be new and updated at the same time.");
    }


    /**
     * Get the {@link MapConverter} for the store.
     *
     * @return
     */

    @Override
    public void deserialize(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showDeserializeHelp();
            return;
        }
        InputStream is;
        boolean isNew = inputLine.hasArg("-new");
        boolean isUpdate = inputLine.hasArg(SHORT_UPDATE_FLAG) || inputLine.hasArg(UPDATE_FLAG);
        if (isNew && isUpdate) {
            say("Sorry. You have asked me to make a new item and update an existing one.");
            return;
        }
        if (!inputLine.hasArg(FILE_FLAG)) {
            say("Missing file argument. Cannot deserialize.");
            return;
        }
        try {
            is = new FileInputStream(inputLine.getNextArgFor(FILE_FLAG));

            XMLMap map = new XMLMap();
            map.fromXML(is);
            is.close();
            // x contains the object that is now of the correct type.
            Identifiable x = getStore().getXMLConverter().fromMap(map, null);
            if (isNew) {
                if (getStore().containsKey(x.getIdentifier())) {
                    say("Error! The object with identifier \"" + x.getIdentifierString() + "\" already exists and you specified the item was new. Aborting.");
                    return;
                }
                getStore().save(x);
                return;
            }
            if (isUpdate) {
                if (!getStore().containsKey(x.getIdentifier())) {
                    say("Error! The object with identifier \"" + x.getIdentifierString() + "\" does not exist and therefore cannot be updated.  Aborting.");
                    return;
                }
                // Get the current one
                Identifiable oldVersion = (Identifiable) getStore().get(x.getIdentifier());
                XMLMap oldValues = new XMLMap();
                getStore().getXMLConverter().toMap(oldVersion, oldValues);
                for (String key : map.keySet()) {
                    oldValues.put(key, map.get(key));

                }
                Identifiable updated = getStore().getXMLConverter().fromMap(oldValues, null);
                getStore().save(updated);

                return;
            }
            if (x.getIdentifier() == null) {
                //handles the case where this is new and needs an identifier created. Only way to get
                // a new unused identifier reliably is to have the store create a new entry then we update that.
                Identifiable c = getStore().create();
                x.setIdentifier(c.getIdentifier());
                say("Created identifier \"" + c.getIdentifierString() + "\".");
            }
            // second case, overwrite whatever.
            getStore().save(x);

            say("done!");
        } catch (Throwable e) {
            say("warning, load file at path \"" + inputLine.getNextArgFor(FILE_FLAG) + "\": " + e.getMessage());
        }
    }

    @Override
    protected int longFormat(Identifiable identifiable) {
        return longFormat(identifiable, false);
    }

    /**
     * Prints a restricted set of keys from the first argument. Note that a missing
     * or empty subset means print everything.
     *
     * @param identifiable
     * @param keySubset
     * @param isVerbose
     * @return
     */
    protected int longFormat(Identifiable identifiable, List<String> keySubset, boolean isVerbose) {
        XMLMap map = new XMLMap();
        getStore().getXMLConverter().toMap(identifiable, map);
        List<String> outputList = StringUtils.formatMap(map,
                keySubset,
                true,
                isVerbose,
                indentWidth(),
                display_width);
        for(String x : outputList){
            say(x);
        }
        return 0;
    }

    protected int longFormat(Identifiable identifiable, boolean isVerbose) {
        return longFormat(identifiable, null, isVerbose);
    }

    int display_width = 120;

    /**
     * Gets a consistent look and feel. If you have to override {@link #longFormat(Identifiable)}
     * and add your own entries, use this.
     *
     * @param leftSide
     * @param rightSide
     * @param leftColumWidth
     * @return
     */
    protected String formatLongLine(String leftSide, String rightSide, int leftColumWidth, boolean isVerbose) {
        int dd = indentWidth() + 3; // the default indent plus the " : " in the middle
        int realWidth = display_width - dd;
        boolean shortLine = rightSide.length() + leftColumWidth + 1 <= realWidth;
        if (isVerbose) {

            List<String> flowedtext = StringUtils.wrap(0, StringUtils.toList(rightSide), realWidth - leftColumWidth);

            StringBuffer stringBuffer = new StringBuffer();
            stringBuffer.append(RJustify(leftSide, leftColumWidth) + " : " + flowedtext.get(0) + ((flowedtext.size() <= 1 && shortLine) ? "" : "\n"));
            boolean isFirstLine = true;
            for (int i = 1; i < flowedtext.size(); i++) {
                if (isFirstLine) {
                    isFirstLine = false;
                    stringBuffer.append(StringUtils.getBlanks(dd + leftColumWidth) + flowedtext.get(i));
                } else {
                    stringBuffer.append("\n" + StringUtils.getBlanks(dd + leftColumWidth) + flowedtext.get(i));
                }
            }
            return stringBuffer.toString();

        }
        return RJustify(leftSide, leftColumWidth) + " : " + truncate(rightSide.replace("\n", "").replace("\r", ""));
    }

    @Override
    public void serialize(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSerializeHelp();
            return;
        }
        OutputStream os = System.out;
        boolean hasFile = false;
        if (inputLine.hasArg(FILE_FLAG)) {
            try {
                os = new FileOutputStream(inputLine.getNextArgFor(FILE_FLAG));
                hasFile = true;
            } catch (FileNotFoundException e) {
                say("warning, could not find file in argument \"" + inputLine.getNextArgFor(FILE_FLAG));
            }
            inputLine.removeSwitchAndValue(FILE_FLAG);
        }

        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("Object not found");
            return;
        }


        XMLMap c = new XMLMap();
        getStore().getXMLConverter().toMap(x, c);

        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> keys = getArgList(inputLine);
            inputLine.removeSwitchAndValue(KEYS_FLAG);
            // c now contains all the fields. We remove anything
            XMLMap subset = new XMLMap();
            // put in the identifier
            MapConverter mc = (MapConverter) getStore().getXMLConverter();

            subset.put(mc.getKeys().identifier(), x.getIdentifierString());
            for (String key : keys) {
                if (c.containsKey(key)) {
                    subset.put(key, c.get(key));
                }
            }
            c = subset; // set it to the right variable to get serialized.
        }

        try {
            c.toXML(os);
            if (hasFile) {
                os.flush();
                os.close();
            }
            say("done!");
        } catch (IOException e) {
            say("Error serializing object.");
        }
    }

    protected void showSearchHelp() {
        say("search " +
                KEY_FLAG + " key [ " +
                SEARCH_REGEX_FLAG + "|" + SEARCH_SHORT_REGEX_FLAG +
                SEARCH_SIZE_FLAG + "] [" +
                SEARCH_LIST_KEYS_FLAG + "] [" +
                SEARCH_DEBUG_FLAG + "] [" +
                LINE_LIST_COMMAND + " | " + VERBOSE_COMMAND + " ] [" +
                SEARCH_RETURNED_ATTRIBUTES_FLAG + " list] condition");
        sayi("Searches the current component for all entries satisfying the condition. You may also specify that the ");
        sayi("condition is a regular expression rather than using simple equality");
        sayi("Invoking this with the -listkeys flag prints out all the keys for this store. Omit that for searches.");
        sayi(KEY_FLAG + " = the name of the key to be searched for");
        sayi(SEARCH_REGEX_FLAG + "|" + SEARCH_SHORT_REGEX_FLAG + " (optional) attempt to interpret the conditional as a regular expression");
        sayi(LINE_LIST_COMMAND + " (optional) print the result in long format.");
        sayi(VERBOSE_COMMAND + " (optional) print the result in verbose format.");
        sayi(SEARCH_SIZE_FLAG + " (optional) print *only* the number of results.");
        sayi(SEARCH_DEBUG_FLAG + " (optional) show stack traces. Only use this if you really need it.");
        sayi(SEARCH_RETURNED_ATTRIBUTES_FLAG + " [attr0,attr1,...] = return only those attributes. " +
                "Note you may specify long or verbose format too.");
        showKeyShorthandHelp();
        sayi("\nE.g.\n");
        sayi("search " + KEY_SHORTHAND_PREFIX + "client_id " + SEARCH_REGEX_FLAG + " \".*07028.*\"");
        sayi("\n(In the clients components) This would find the clients whose identifiers contain the string 07028");
        sayi("\nE.g.\n");
        sayi("search " + KEY_FLAG + " email " + SEARCH_SHORT_REGEX_FLAG + " \".*bigstate\\.edu.*\"");
        sayi("\n(in the clients or user component) This would match all email addresses from that institution bigstate.edu. \n");
        sayi("Note that the period must be escaped for a regex.");
        sayi("\nE.g.\n");
        sayi("search " + KEYS_FLAG + " client_id " +
                SEARCH_SHORT_REGEX_FLAG + " " +
                SEARCH_RETURNED_ATTRIBUTES_FLAG + "[name, email] " +
                ".*237.*"
        );
        sayi("\nThis would search for all client id's that contain the string 237 and only print out the name and email from those.");
    }

    static String SEARCH_LIST_KEYS_FLAG = "-listKeys";
    static String SEARCH_REGEX_FLAG = "-regex";
    static String SEARCH_SHORT_REGEX_FLAG = "-r";
    static String SEARCH_SIZE_FLAG = "-size";
    static String SEARCH_DEBUG_FLAG = "-debug";
    static String SEARCH_RETURNED_ATTRIBUTES_FLAG = "-out";


    @Override
    public void search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSearchHelp();
            return;
        }
        SerializationKeys keys = ((MapConverter) getStore().getXMLConverter()).getKeys();
        boolean showStackTraces = inputLine.hasArg(SEARCH_DEBUG_FLAG);
        if (inputLine.hasArg(SEARCH_LIST_KEYS_FLAG)) {
            if (getStore().getXMLConverter() instanceof MapConverter) {
                say("keys");
                say("-------");
                for (String key : keys.allKeys()) {
                    say(key);
                }
            }
            return;
        }
        List<String> returnedAttributes = null;
        if (inputLine.hasArg(SEARCH_RETURNED_ATTRIBUTES_FLAG)) {
            returnedAttributes = getArgList(inputLine);
        }
        String key = getKeyArg(inputLine);
        if (key != null) {
            List<Identifiable> values = null;
            try {
                values = getStore().search(
                        key,
                        inputLine.getLastArg(),
                        inputLine.hasArg(SEARCH_REGEX_FLAG) || inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG));
            } catch (Throwable t) {
                if (showStackTraces) {
                    t.printStackTrace();
                }
                if (t.getCause() == null) {
                    say("Sorry, that didn't work:" + t.getMessage());
                } else {
                    say("Sorry, that didn't work:" + t.getCause().getMessage());
                }
                return;
            }
            if (values.isEmpty()) {
                say("no matches");
            }
            if (inputLine.hasArg(SEARCH_SIZE_FLAG)) {
                say("Got " + values.size() + " results");
                return;
            }
            for (Identifiable identifiable : values) {
                if (returnedAttributes != null) {
                    longFormat(identifiable, returnedAttributes, inputLine.hasArg(VERBOSE_COMMAND));
                    if (1 < values.size()) {
                        say("-----"); // or the output runs together
                    }
                } else {
                    say(format(identifiable));
                }     // search -key token_id -r -out [parent_id, valid] .*oauth2.*
            }
            say("\ngot " + values.size() + " match" + (values.size() == 1 ? "." : "es."));
        } else {
            say("Sorry, you must specify a key for the search. Try typing \nsearch " + SEARCH_LIST_KEYS_FLAG + "\n for all available keys");
        }

    }

    @Override
    protected void showLSHelp() {
        say("ls [" + LINE_LIST_COMMAND + "  | " + VERBOSE_COMMAND + " | " + ALL_LIST_COMMAND + "] | [" + KEY_FLAG + " key | " + KEYS_FLAG + " array] id");
        sayi("Lists information about the contents of the store, an entry and individual values of the entry.");
        sayi("When listing multiple entries, tools will use the most numbers from the most recent call to this.");
        sayi("A line listing is tabular and will shorten entries that are too long, ending them with " + ELLIPSIS);
        sayi("A verbose command will format every bit of every entry within the margins.");
        showKeyShorthandHelp();
        say("E.g.");
        sayi("ls " + LINE_LIST_COMMAND + "  " + ALL_LIST_COMMAND);
        sayi("Prints out the line form of *every* object in this store. This may be simply huge");
        say("E.g.");
        sayi("ls");
        sayi("Prints out the short form of *every* object in this store. This may also be huge.");
        sayi("If you are using this to find things, you probably want to look at the search command");
        say("E.g.");
        sayi("ls " + LINE_LIST_COMMAND + "  /foo:bar");
        sayi("Prints a line format for the entry with id foo:bar");
        say("E.g.");
        sayi("ls " + VERBOSE_COMMAND + " /foo:bar");
        sayi("prints out a verbose listing of the entry with id foo:bar.");
        say("E.g.");
        sayi("ls " + KEY_FLAG + " id /foo:bar");
        sayi(">   foo:bar");
        sayi("Prints out the id property for the object with identifier foo:bar");
        sayi("");
        sayi("You may also supply a list of keys in an array of the form [key0,key1,...].");
        say("E.g.");
        sayi("ls " + KEYS_FLAG + " [id,callback_uris,create_ts] /foo:bar");
        sayi("would print the id, callback_uri and create_ts properties for the object with id");
        sayi("foo:bar. ");
        sayi("\nSee also list_keys, search");
    }

    @Override
    protected void showRMHelp() {
        say("rm [" + KEY_FLAG + " | " + KEYS_FLAG + " list] id");
        sayi("Remove a property from this the object with the given value.");
        sayi("If you supply a list, all of the properties in the list will be removed");
        sayi("No list of keys means to remove the entire object from the store (!)");
        showKeyShorthandHelp();
        say("E.g.");
        sayi("rm " + KEY_SHORTHAND_PREFIX + "error_uri /foo:bar");
        sayi("Removes the value of the property 'error_uri' from the object with id foo:bar");
        say("E.g.");
        sayi("rm /foo:bar");
        sayi("removes the object with id foo:bar completely from the store");
        say("E.g.");
        sayi("rm " + KEYS_FLAG + " [error_uri,home_uri] /foo:bar");
        sayi("removes the values of the properties error_uri and home_uri from the object with id");
        sayi("equal to foo:bar");
    }

    /**
     * Called if there is additional clean up needed. For instance, removing a client
     * requires removing its approval record.
     *
     * @param identifiable
     */
    protected void rmCleanup(Identifiable identifiable) {
    }

    @Override
    public void rm(InputLine inputLine) throws IOException {
        if (showHelp(inputLine)) {
            showRMHelp();
            return;
        }
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("Object not found");
            return;
        }
        String key = getKeyArg(inputLine);
        // if the request does not have new stuff, do old stuff.
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            super.rm(inputLine);
            rmCleanup(identifiable);
            return;
        }
        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> array = getArgList(inputLine);

            if (array == null) {
                say("sorry, but this requires a list for this option.");
                return;
            }
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }
            removeEntries(identifiable, array);
        }
        if (key != null) {
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }

            removeEntry(identifiable, key);
            say("removed attribute \"" + key + "\"");
        }
        //    rmCleanup(identifiable);
    }

    @Override
    public void ls(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showLSHelp();
            return;
        }
        String key = getKeyArg(inputLine);
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            super.ls(inputLine);
            return;
        }
        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> array = getArgList(inputLine);

            if (array == null) {
                say("sorry, but this requires a list for this option.");
                return;
            }
            Identifiable identifiable = findItem(inputLine);
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }

            showEntries(identifiable, array, inputLine.hasArg(VERBOSE_COMMAND));
            return;
        }
        if (key != null) {
            Identifiable identifiable = findItem(inputLine);
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }
            showEntry(identifiable, key, inputLine.hasArg(VERBOSE_COMMAND));
        }

    }

    @Override
    protected void showUpdateHelp() {
        say("update [" + KEY_FLAG + " key [" + VALUE_FLAG + " value | " + FILE_FLAG + " file_path " + JSON_FLAG + "]]" +
                "[" + KEYS_FLAG + " array] index\n");
        sayi("where the index is the index in the list command.");
        sayi("This has three modes. Just an id will prompt you for every value to update.");
        say("Alternately, you may either specify a single key + value OR you may specify an array of keys");
        sayi("of the form [key0,key1,...]. (The list_keys command will tell what the keys are.)");
        sayi("The " + KEYS_FLAG + " will act on all the keys supplied.");
        showKeyShorthandHelp();
        say("E.g.");
        sayi("update /foo:bar");
        sayi("no arguments means to interactively ask for every attribute. /foo:bar is the identifier for this object.");
        say("E.g.");
        sayi("update -key cfg -file /path/to/file /foo:bar");
        sayi("read the contents of the file (as a string) into the attribute");
        say("E.g.");
        sayi("update " + KEY_SHORTHAND_PREFIX + "name " + VALUE_FLAG + " \"My client\" /foo:bar");
        sayi("This changes the value of the 'name' attribute to 'My client' for the object with id 'foo:bar'");
        sayi("Note that no prompting is done! The value will be updated.");
        say("E.g.");
        sayi("update " + KEYS_FLAG + " [name,callback_uri] /foo:bar");
        sayi("This would prompt to update the values for the 'name' and 'callback_uri' properties");
        sayi("of the object with id 'foo:bar'");
        sayi("A few notes. If the value of the property is a JSON object, you can edit it.");
        sayi("If the value of the property is an array, then you may add a value, delete a value,");
        sayi("replace the entire contents (new entries are comma separated) or simply clear the .");
        sayi("entire list of entries. You may also back out of the update request.");
        say("See also list_keys");
    }


    String KEY_FLAG = "-key";
    String VALUE_FLAG = "-value";
    String KEYS_FLAG = "-keys";

    @Override
    public void update(InputLine inputLine) throws IOException {

        if (showHelp(inputLine)) {
            showUpdateHelp();
            return;
        }
        if (inputLine.hasArg(VALUE_FLAG) && inputLine.hasArg(FILE_FLAG)) {
            say("Sorry, you have specified both a value and a file for the value.");
            return;
        }
        String key = getKeyArg(inputLine);
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            super.update(inputLine);
            return;
        }

        boolean hasFileFlag = inputLine.hasArg(FILE_FLAG);
        Identifiable identifiable = null;
        XMLMap map = null;
        // Since the value can be anything --like a path to a file. e.g. /tmp/foo or
        // an integer, we *have* to remove arguments until we can see what the
        // actual id is.
        boolean gotOne = false;
        String value = null;
        if (key == null) {
            say("sorry, but \"" + key + "\" is not a recognized attribute.");
            return;
        } else {
            // inputLine.removeSwitchAndValue(KEY_FLAG);
            if (inputLine.hasArg(VALUE_FLAG)) {
                value = inputLine.getNextArgFor(VALUE_FLAG);
                inputLine.removeSwitchAndValue(VALUE_FLAG);
            }
            if (hasFileFlag) {
                try {
                    value = FileUtil.readFileAsString(inputLine.getNextArgFor(FILE_FLAG));
                } catch (Throwable throwable) {
                    say("Sorry, but I could not seem to read the file named \"" + inputLine.getNextArgFor(FILE_FLAG) + "\"");
                    return;
                }
                inputLine.removeSwitchAndValue(FILE_FLAG);

            }
            identifiable = findItem(inputLine);
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }
            map = toXMLMap(identifiable);
            if (value == null) {
                gotOne = updateSingleValue(map, key);
            } else {
                map.put(key, value);
                gotOne = true;
            }
        }
        if (inputLine.hasArg(VALUE_FLAG)) {
            say("Malformed update request. If you specify a value, you must specify a single key.");
            return;
        }


        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> keys = getArgList(inputLine);
            inputLine.removeSwitchAndValue(KEYS_FLAG);
            identifiable = findItem(inputLine);
            if (identifiable == null) {
                say("sorry, I could not find that object. Check your id.");
                return;
            }
            map = toXMLMap(identifiable);

            for (String k : keys) {
                gotOne = updateSingleValue(map, k) || gotOne; // order matters!
            }
        }

        if (gotOne) {
            getStore().save(fromXMLMap(map));
        }

    }

    protected JSONArray updateSingleValue(String key, JSONArray currentValue) throws IOException {
        say("current value=" + currentValue);
        String action = getInput("Add, clear, delete, replace or exit?(a/c/d/r/x)", "a").toLowerCase();
        if (action.equals("x")) {
            return null; // do nothing.
        }
        if (action.equals("r")) {
            say("Enter the new elements with commas between them");
        }
        String newValue = null;
        if (action.equals("d")) {
            newValue = getInput("Value to remove", "");
        } else {
            newValue = getInput("New value", "");
        }
        switch (action) {
            case "a":
                // Append a value to the list
                currentValue.add(newValue);
                return currentValue;
            case "c":
                // clear the entire contents
                currentValue.clear();
                return currentValue;
            case "d":
                // delete a single value in the list
                currentValue.remove(newValue);
                return currentValue;
            case "r":
                // replace the entire contents.
                currentValue.clear();
                if (newValue.equals("")) {
                    return currentValue;
                }
                StringTokenizer st = new StringTokenizer(newValue, ",");
                while (st.hasMoreElements()) {
                    currentValue.add(st.nextToken());
                }
                return currentValue;

        }
        say("sorry, I did not understand what you want to do.");
        return null;
    }

    protected boolean supportsQDL() {
        return false;
    }

    /**
     * The contract is that this gets the entire current config and updates <i>exactly</i>
     * the bits relating to QDL. This is then saved elsewhere.
     *
     * @param currentConfig
     * @return
     */
    protected JSONObject loadQDLScript(JSONObject currentConfig) throws IOException {
        return currentConfig; // do nothing.
    }

    protected boolean updateSingleValue(XMLMap map, String key) throws IOException {
        String currentValue = map.getString(key);

        JSON json = null;
        if (currentValue != null) {
            // edge case to avoid  a &^*%@! JSON null object.
            // JSONNull means parsing a null into a JSON object that bombs everyplace like a regular null.,
            // i.e,. every operation throws the equivalent of an NPE.
            // They just do it so they have a typed null of type JSON...
            try {
                json = JSONSerializer.toJSON(currentValue);
            } catch (Throwable t) {
                // ok, it's not JSON
            }
        }

        if (json == null) {
            // This handles every other value type...
            String newValue = getInput("Enter new value for " + key + " ", currentValue);
            if (newValue.equals(currentValue)) {
                return false;
            }
            map.put(key, newValue);
            return true;
        }
        if (json != null && (json instanceof JSONObject)) {
            if (supportsQDL()) {
                boolean loadQDL = getInput("Load only a QDL script or edit the full config? (q/f)", "f").equalsIgnoreCase("q");
                if (loadQDL) {
                    JSONObject oldCfg = (JSONObject) json;
                    JSONObject qdlcfg = loadQDLScript(oldCfg);

                    if (qdlcfg == null) {
                        return false;
                    } // they cancelled out of it

                    map.put(key, oldCfg.toString());
                    return true;
                } else {
                    JSONObject newConfig = (JSONObject) inputJSON((JSONObject) json, "client configuration");
                    if (newConfig == null) {
                        return false;
                    } // user cancelled
                    map.put(key, newConfig);
                    return true;
                }
            } else {
                JSONObject newJSON = inputJSON((JSONObject) json, key);
                if (newJSON == null) {
                    return false;
                } // user cancelled
                map.put(key, newJSON);
                return true;
            }
        }
        if (json != null && (json instanceof JSONArray)) {
            JSONArray newArray = updateSingleValue(key, (JSONArray) json);
            // really hard to tell if the array is updated in the general case.
            // so just always save it.
            if (newArray == null) {
                return false;
            }
            map.put(key, newArray);
            return true;
        }
        return false; // Just in case, do nothing.
    }


    /**
     * Allows for entering a new JSON object. This permits multi-line entry so formatted JSON can be cut and pasted
     * into the command line (as long as there are no blank lines). This will validate the JSON, print out a message and
     * check that you want to keep the new JSON. Note that you cannot overwrite the value of a configuration at this point
     * mostly as a safety feature. So hitting return or /exit will have the same effect of keeping the current value.
     *
     * @param oldJSON
     * @return null if the input is terminated (so retain the old object)
     */
    protected JSONObject inputJSON(JSONObject oldJSON, String key) throws IOException {
        if (oldJSON == null) {
            sayi("no current value for " + key);
        } else {
            sayi("current value for " + key + ":");
            say(oldJSON.toString(1));
        }
        sayi("Enter new JSON value. An empty line terminates input. Entering a line with " + EXIT_COMMAND + " will terminate input too.\n Hitting " + CLEAR_BUFFER_COMMAND + " will clear the contents of this.");
        String rawJSON = "";
        boolean redo = true;
        while (redo) {
            try {
                String inLine = readline();
                while (!isEmpty(inLine)) {
                    if (inLine.equals(CLEAR_BUFFER_COMMAND)) {
                        return new JSONObject();
                    }
                    rawJSON = rawJSON + inLine + "\n";
                    inLine = readline();
                }
            } catch (ExitException x) {
                // ok, so user terminated input. This ends the whole thing
                return null;
            }
            // if the user just hits return with no input, do nothing. This lets them skip over unchanged entries.
            if (rawJSON.isEmpty()) {
                return null;
            }
            try {
                JSONObject json = null;
                // Old was the following line.
                //json = JSONObject.fromObject(rawJSON);
                // new allows for HOCON at command line.
                Config config = ConfigFactory.parseString(rawJSON);
                json = JSONObject.fromObject(config.root().render(ConfigRenderOptions.concise()));
                sayi("Success! JSON is valid.");
                return json;
            } catch (Throwable t) {
                sayi("uh-oh... It seems this was not a valid JSON object. The parser message reads:\"" + t.getMessage() + "\"");
                redo = isOk(getInput("Try to re-enter this?", "true"));
            }
        }

        return null;
    }

    /**
     * Once an object is found in the store, convert it to JSON so that the properties may be
     * accessed in a canonical way. This lets us take any identifiable object and manipulate its
     * properties without knowing anything else about it.
     *
     * @param identifiable
     * @return
     */
    protected XMLMap toXMLMap(Identifiable identifiable) {
        Identifiable x = (Identifiable) getStore().get(identifiable.getIdentifier());
        XMLMap map = new XMLMap();
        MapConverter mapConverter = (MapConverter) getStore().getXMLConverter();
        mapConverter.toMap(x, map);
        return map;
    }

    /**
     * Take the <b>updated</b> values for the object and return a new, updated object.
     * This does not store it, so you have to do that if you want to keep the changes.
     *
     * @param map
     */
    protected Identifiable fromXMLMap(XMLMap map) {
        Identifiable identifiable = getStore().create();
        MapConverter mapConverter = (MapConverter) getStore().getXMLConverter();
        mapConverter.fromMap(map, identifiable);
        return identifiable;
    }

    /**
     * Add to an existing entry.
     *
     * @param identifiable
     * @param jjj
     */
    protected void addEntry(Identifiable identifiable, JSON jjj) {
        if (!(jjj instanceof JSONObject)) {
            say("sorry, but that is not a valid JSON object for this operation.");
            return;
        }
        JSONObject json = (JSONObject) jjj;
        XMLMap object = toXMLMap(identifiable);
        for (Object k : json.keySet()) {
            String key = k.toString();
            Object newValue = json.get(key);
            if (hasKey(key)) {
                Object currentValue = object.containsValue(k);
                if (currentValue == null) {
                    object.put(key, newValue);
                } else {
                    if (currentValue instanceof JSONArray) {
                        ((JSONArray) currentValue).add(newValue);
                    } else {
                        object.put(key, newValue);
                    }
                }
            } else {
                say("sorry, but \"" + key + "\" is not a recognized key. Skipping...");
            }
        }
        getStore().save(fromXMLMap(object));
    }

    protected void addEntry(Identifiable identifiable, String key, String value) {
        XMLMap object = toXMLMap(identifiable);
        if (hasKey(key)) {
            Object currentValue = object.get(key);
            if (currentValue == null) {
                object.put(key, value);
            } else {
                if (currentValue instanceof JSONArray) {
                    ((JSONArray) currentValue).add(value);
                } else {
                    object.put(key, value);
                }
            }
        } else {
            say("sorry, but \"" + key + "\" is not a recognized key. Skipping...");

        }
        getStore().save(fromXMLMap(object));
    }


    protected void removeEntries(Identifiable identifiable, List<String> keys) {
        XMLMap object = toXMLMap(identifiable);
        boolean gotOne = false;
        for (String key : keys) {
            if (hasKey(key)) {
                if (object.containsKey(key)) {
                    object.remove(key);
                    gotOne = true;
                }
            }
        }
        if (gotOne) {
            getStore().save(fromXMLMap(object));
        }

    }

    protected void removeEntry(Identifiable identifiable, String key) {
        XMLMap object = toXMLMap(identifiable);
        if (hasKey(key)) {
            if (object.containsKey(key)) {
                object.remove(key);
                getStore().save(fromXMLMap(object));
            } else {
                say("key \"" + key + "\" not found for this object.");
            }
        }
    }


    protected void showEntries(Identifiable identifiable, List<String> keys, boolean isVerbose) {
        XMLMap object = toXMLMap(identifiable);
        int leftWidth = 0;
        TreeMap<String, String> tMap = new TreeMap<>();
        for (String x : keys) {
            leftWidth = Math.max(leftWidth, x.length());
            tMap.put(x, object.getString(x));
        }

        for (String key : tMap.keySet()) {
            String v = tMap.get(key);
            // Suppress null entries. Record empty ones.
            if (!StringUtils.isTrivial(v)) {
                say(formatLongLine(key, v, leftWidth, isVerbose));
            }
        }
    }

    protected void showEntry(Identifiable identifiable, String key, boolean isVerbose) {
        if (hasKey(key)) {
            XMLMap object = toXMLMap(identifiable);
            if (object.containsKey(key)) {
                Object v = object.get(key);
                try {
                    JSON json = JSONSerializer.toJSON(v);
                    say(key + ":\n" + json.toString(1));

                } catch (Throwable t) {
                    say(key + " :\n" + object.get(key));
                }
            } else {
                say("(no value)");
            }
        } else {
            say("sorry, but \"" + key + "\" is not a recognized key. Skipping...");

        }

    }

    protected boolean hasKey(String key) {
        XMLConverter xmlConverter = getStore().getXMLConverter();
        if (xmlConverter instanceof MapConverter) {
            MapConverter mc = (MapConverter) xmlConverter;
            return mc.getKeys().allKeys().contains(key);
        }
        return false;
    }

    public void list_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showListKeysHelp();
            return;
        }
        XMLConverter xmlConverter = getStore().getXMLConverter();
        if (xmlConverter instanceof MapConverter) {
            MapConverter mc = (MapConverter) xmlConverter;
            TreeSet<String> kk = new TreeSet<>();
            kk.addAll(mc.getKeys().allKeys());
            // print them in order.
            for (String key : kk) {
                say(key);
            }
        }
    }

    protected void showListKeysHelp() {
        say("list_keys");
        sayi("This lists the keys of the current store.");
    }

    @Override
    public void edit(InputLine inputLine) {
        Identifiable x = findItem(inputLine);
        XMLMap c = new XMLMap();
        getStore().getXMLConverter().toMap(x, c);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            c.toXML(baos);
            baos.close();
            String raw = new String(baos.toString("UTF-8"));
            LineEditor lineEditor = new LineEditor(raw);
            lineEditor.execute();
            String rc = getInput("save (y/n)?", "y");
            if (rc.equals("y")) {
                byte[] bytes = lineEditor.bufferToString().getBytes("UTF-8");
                XMLMap map = new XMLMap();
                ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
                map.fromXML(bais);
                bais.close();
                Identifiable identifiable = getStore().getXMLConverter().fromMap(map, null);
                getStore().save(identifiable);
            } else {
                say("changes ignored.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
    }


    String LIST_START_DELIMITER = "[";
    String LIST_END_DELIMITER = "]";
    String LIST_SEPARATOR = ",";

    /**
     * Slightly special case. This will look on the input line and extract a list of the form
     * <pre>
     *     [a,b,c,...]
     * </pre>
     * So to avoid having a lot of parsing (and the fact that there is pretty much at most one
     * array per line) this will take everything between [ ] and try to turn it in to a list.
     * The alternative would be make the list syntax have to conform to
     * {@link InputLine}'s fairly primitive system of checking for flags.
     *
     * @param inputLine
     * @return
     */
    protected List<String> getArgList(InputLine inputLine) {
        List<String> list = new ArrayList<>();
        String rawLine = inputLine.getOriginalLine();
        if (rawLine == null || rawLine.isEmpty()) {
            return list;
        }
        int startListIndex = rawLine.indexOf(LIST_START_DELIMITER);
        int endListIndex = rawLine.indexOf(LIST_END_DELIMITER);
        if (startListIndex == -1 || endListIndex == -1) {
            return list;
        }
        String rawList = rawLine.substring(startListIndex + 1, endListIndex);
        StringTokenizer st = new StringTokenizer(rawList, LIST_SEPARATOR);
        while (st.hasMoreElements()) {
            list.add(st.nextToken().trim());
        }

        return list;
    }

    String JSON_FLAG = "-json";

    public static void main(String[] args) {
        CommandLineTokenizer CLT = new CommandLineTokenizer();
        String raw = "update -add -json '{\"fnord\":[\"blarf0\",\"blarf1\"]}' /foo:bar";

        Vector v = CLT.tokenize(raw);
        System.out.println(v);
        InputLine inputLine = new InputLine(v);
    }

    MapConverter mapConverter = null;

    protected MapConverter getMapConverter() {
        if (mapConverter == null) {
            XMLConverter xmlConverter = getStore().getXMLConverter();
            if (!(xmlConverter instanceof MapConverter)) {
                warn("internal error: The XML converter for the store is not a MapConverter.");
                say("internal error: check logs");
                return null;
            }
            mapConverter = (MapConverter) xmlConverter;
        }
        return mapConverter;
    }

    protected long getVersionFromID(Identifier id) {
        URI uri = id.getUri();
        String fragment = uri.getFragment();
        if (StringUtils.isTrivial(fragment)) {
            return -1L;
        }
        try {
            return Long.parseLong(fragment.substring(fragment.indexOf(ARCHIVE_VERSION_SEPARATOR_TAG) + 1));
        } catch (NumberFormatException nfx) {
            return -1L;
        }


    }

    /**
     * @param inputLine
     * @throws Exception
     * @experimental
     */
    public void archive(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showArchiveHelp();
            return;
        }
        // special case -- show accepts the version number. If we aren't careful, the version number
        // will get fed to the findItem call and give very bad results.
        // Intercept it here for later if needed.
        boolean isShow = inputLine.hasArg(ARCHIVE_SHOW_FLAG);
        String showArg = null;
        if (isShow) {
            showArg = inputLine.getNextArgFor(ARCHIVE_SHOW_FLAG);
            inputLine.removeSwitchAndValue(ARCHIVE_SHOW_FLAG);
        }
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("sorry, I could not find that object. Check your id.");
            return;
        }
        MapConverter mc = getMapConverter();

          /*
          Contract is that identifiers never have fragments -- these are used by the system for information.
          In this case, a fragment of the form version_x where x is a non-negative integer is added.
           */
        if (inputLine.hasArg(ARCHIVE_VERSIONS_FLAG)) {
            // Grab each client and run through information about them
            List<Identifiable> values = getStore().search
                    (mc.getKeys().identifier(),
                            identifiable.getIdentifierString() + ".*",
                            true);


            TreeMap<Long, Identifiable> sortedMap = new TreeMap<>();
            // There is every reason to assume that there will be gaps ion the number sequences over time.
            // create a new set of these and manage the order manually.

            for (Identifiable x : values) {
                long version = getVersionFromID(x.getIdentifier());
                if (-1 < version) {
                    sortedMap.put(version, x);
                }
            }
            if (sortedMap.isEmpty()) {
                sayi("(no archived versions)");
                return;
            }
            say("archived versions of " + identifiable.getIdentifierString() + ":");
            // Now we run through them all in order
            for (Long index : sortedMap.keySet()) {
                say(archiveFormat(sortedMap.get(index)));
            }
            return;
        }
        if (inputLine.hasArg(ARCHIVE_RESTORE_FLAG)) {
            String rawTargetVersion = inputLine.getNextArgFor(ARCHIVE_RESTORE_FLAG);
            boolean doLatest = rawTargetVersion.equals(ARCHIVE_LATEST_VERSION_ARG);
            DoubleHashMap<URI, Long> versionNumbers = getVersions(identifiable);
            if (versionNumbers.isEmpty()) {
                say("no versions found for \"" + identifiable.getIdentifierString() + "\"");
                return;
            }
            long targetVersion = 0L;
            if (doLatest) {
                targetVersion = getLatestVersionNumber(versionNumbers);
            } else {
                try {
                    targetVersion = Long.parseLong(rawTargetVersion);
                } catch (NumberFormatException nfx) {
                    say("sorry, but \"" + rawTargetVersion + "\" could not be parsed as a version number");
                    return;
                }
            }
            URI id = versionNumbers.getByValue(targetVersion);
            if (id == null) {
                say("sorry, but the version you requested \"" + rawTargetVersion + "\" does not exist.");
                return;
            }
            Identifiable storedVersion = (Identifiable) getStore().get(BasicIdentifier.newID(id));
            if (getInput("Are you sure that you want to replace the current version with version \"" + targetVersion + "\"?(y/n)", "n").equals("y")) {
                // TODO Maybe put some version information inside the object?????
                // Practical problem is that there is no place to necessarily put it in the general case.
                // So version number, timestamp for version?
                // What to do with these if the version is restored?
                storedVersion.setIdentifier(identifiable.getIdentifier());
                getStore().save(storedVersion);
            } else {
                say("aborted.");
                return;
            }

        }
        if (isShow) {
            long targetVersion = -1L;

            DoubleHashMap<URI, Long> versionNumbers = getVersions(identifiable);
            if (showArg.equalsIgnoreCase(ARCHIVE_LATEST_VERSION_ARG)) {
                targetVersion = getLatestVersionNumber(versionNumbers);
            } else {
                try {
                    targetVersion = Long.parseLong(showArg);
                } catch (NumberFormatException nfx) {
                    say("sorry but the version number you supplied \"" + targetVersion + "\" is not a number.");
                    return;
                }
            }
            if (versionNumbers.getByValue(targetVersion) == null) {
                say("sorry, but " + targetVersion + " is not the number of a version for \"" + identifiable.getIdentifierString() + "\".");
                return;
            }
            Identifiable target = (Identifiable) getStore().get(BasicIdentifier.newID(versionNumbers.getByValue(targetVersion)));
            longFormat(target, true); // show everything!
            return;
        }
        // If we are at this point, then the user wants to version the object
        DoubleHashMap<URI, Long> versionNumbers = getVersions(identifiable);
        long newIndex = getLatestVersionNumber(versionNumbers) + 1;
        if (!getInput("Archive object \"" + identifiable.getIdentifierString() + "\"?(y/n)", "n").equals("y")) {
            say("aborted.");
            return;
        }
        // last check
        if (newIndex < 0) {
            say("internal error: check logs");
            warn("error: in creating a version, a negative version number was encountered. This implies something is off with auto-numbering.");
            return;
        }
        // to and from map are charged with being faithful at all times, so we use these to clone the
        Identifiable newVersion = getStore().create();
        XMLMap map = new XMLMap();
        mc.toMap(identifiable, map);

        mc.fromMap(map, newVersion);

        Identifier newID = createdVersionedID(identifiable.getIdentifier(), newIndex);
        newVersion.setIdentifier(newID);
        getStore().save(newVersion);


    }

    String ARCHIVE_VERSION_TAG = "version";
    String ARCHIVE_VERSION_SEPARATOR_TAG = "=";
    String ARCHIVE_VERSIONS_FLAG = "-versions";
    String ARCHIVE_RESTORE_FLAG = "-restore";
    String ARCHIVE_SHOW_FLAG = "-show";
    String ARCHIVE_LATEST_VERSION_ARG = "latest";

    protected Identifier createdVersionedID(Identifier id, long version) {
        URI uri = id.getUri();
        String rawURI = uri.toString();
        rawURI = rawURI.substring(rawURI.indexOf("#") + 1);
        rawURI = rawURI + "#" + ARCHIVE_VERSION_TAG + ARCHIVE_VERSION_SEPARATOR_TAG + Long.toString(version);
        uri = URI.create(rawURI);
        return BasicIdentifier.newID(uri);

    }

    /**
     * Get the latest version number or return a -1 if no versions present.
     *
     * @param versionNumbers
     * @return
     */
    protected Long getLatestVersionNumber(DoubleHashMap<URI, Long> versionNumbers) {
        if (versionNumbers.isEmpty()) {
            return -1L;
        }
        long maxValue = 0L;
        for (URI key : versionNumbers.keySet()) {
            maxValue = Math.max(maxValue, versionNumbers.get(key));
        }
        return maxValue;
    }

    /**
     * For a given object in the store, return all the versions associated with it in a
     * {@link DoubleHashMap}.
     *
     * @param identifiable
     * @return
     */
    protected DoubleHashMap<URI, Long> getVersions(Identifiable identifiable) {
        MapConverter mc = getMapConverter();
        List<Identifiable> values = getStore().search
                (mc.getKeys().identifier(),
                        identifiable.getIdentifierString() + ".*",
                        true);

        // now we have to look through the list of clients and determine which is the one we want
        DoubleHashMap<URI, Long> versionNumbers = new DoubleHashMap<>();
        for (Identifiable value : values) {
            URI uri = value.getIdentifier().getUri();
            String fragment = uri.getFragment();
            if (!StringUtils.isTrivial(fragment)) {
                // This does two things. First, it will no show the base version as archived
                // and secondly, will only add those with a valid versioning fragment
                String rawIndex = fragment.substring(1 + fragment.indexOf(ARCHIVE_VERSION_SEPARATOR_TAG));

                try {
                    if (!StringUtils.isTrivial(rawIndex)) {
                        versionNumbers.put(uri, Long.parseLong(rawIndex));
                    }
                } catch (Throwable t) {

                }
            }

        }
        return versionNumbers;
    }

    protected void showArchiveHelp() {
        say("archive [-versions] | [-restore version] [id] - archive an object");
        say("This will either create a copy of the current version or restore a versioned object.");
        say("archive [id]");
        sayi(" version the object, assigning it the last version.");
        say("archive -versions [id]  ");
        sayi("list the versions of an object");
        say("archive -latest");
        sayi("Show the number of the latest version (-1 if no versions exist)");

        say("archive -restore (number | latest) [id]");
        sayi("Restore the given version of this. If a number is given, use that. If the word \"latest\" (no quotes");
        sayi("is used, give back the latest version.");
    }

    protected String archiveFormat(Identifiable id) {
        return format(id);
    }

    public void copy(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showCopyHelp();
            return;
        }
        boolean forceIt = inputLine.hasArg("-f");
        String sourceString = inputLine.getArg(1); // zero-th arg is name of command.
        String targetString = inputLine.getArg(2);
        Identifier sourceId = null;
        Identifier targetId = null;
        try {
            sourceId = BasicIdentifier.newID(sourceString);
        } catch (Throwable t) {
            say("sorry, but the first argument \"" + sourceString + "\" is not a valid identifier");
            return;
        }
        try {
            targetId = BasicIdentifier.newID(targetString);
        } catch (Throwable t) {
            say("sorry, but the second argument \"" + targetString + "\" is not a valid identifier");
            return;
        }

        Identifiable source = (Identifiable) getStore().get(sourceId);
        if (!forceIt && getStore().containsKey(targetId)) {
            say("sorry, but \"" + targetId + "\" already exists. Consider using the -f flag if you need to overwrite it.");
            return;
        }

        MapConverter mc = getMapConverter();
        Identifiable newVersion = getStore().create();
        XMLMap map = new XMLMap();
        mc.toMap(source, map);

        mc.fromMap(map, newVersion);
        newVersion.setIdentifier(targetId);
        getStore().save(newVersion);

    }

    private void showCopyHelp() {
        say("copy source target [-f] - copy source to target, possibly forcing the issue");
        say("This will create a complete copy of source and store it with the id of target.");
        say("Default is to refuse to do this if target exists. If you supply the -f flag, then");
        say("target will be overwritten if it exists.");
        say("This only makes a simple copy. If this is, e.g., a client, you will need to approve it, change secret etc.");
        say("Note: source and target are identifiers (no lead /).");
        say("E.g. In the client store:\n");
        say("  client>copy dev:command.line dev:no_cfg\n");
        say("would take the client configuration with id dev:command.line and create a new client config. that is");
        say("identical except with id dev:no_cfg. In this case, as a new client, it needs to be approved.");
    }

    public static String KEY_SHORTHAND_PREFIX = ">";

    /**
     * resolves key shorthand of >key_name or -key key_name
     *
     * @param inputLine
     * @return
     */
    protected String getKeyArg(InputLine inputLine) {
        if (inputLine.hasArg(KEY_FLAG)) {
            return inputLine.getNextArgFor(KEY_FLAG);
        }
        if(inputLine.size() <=1){
            // so no actual arguments supplied.
            return null;
        }

        // have to search
        for (int i = 1; i < inputLine.size(); i++) {
            String arg = inputLine.getArg(i);
            if (arg.startsWith(KEY_SHORTHAND_PREFIX)) {
                String out = arg.substring(1);
                // check that it is a key. If not, ignore it.
                if (getMapConverter().getKeys().allKeys().contains(out)) {
                    inputLine.removeSwitch(arg); // or it can screw up other things.
                    return out;
                }
            }
        }
        return null;
    }

    protected void showKeyShorthandHelp() {
        sayi("Note: The argument idiom '-key key_name' may be replaced with '" + KEY_SHORTHAND_PREFIX + "key_name' as a shorthand");
    }
}
