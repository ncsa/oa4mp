package edu.uiuc.ncsa.myproxy.oa4mp.server;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigRenderOptions;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.cli.*;
import edu.uiuc.ncsa.security.util.cli.editing.EditorEntry;
import edu.uiuc.ncsa.security.util.cli.editing.EditorUtils;
import edu.uiuc.ncsa.security.util.cli.editing.LineEditor;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.io.*;
import java.net.URI;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;

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
        say("serialize  [-file path] index");
        sayi("Usage: XML serializes an object and either shows it on the ");
        sayi("   command line or put it in a file. Cf. deserialize.");
        sayi("See also: deserialize.");
    }

    protected void showDeserializeHelp() {
        say("deserialize  [-new] -file path [" + SHORT_UPDATE_FLAG + "|" + UPDATE_FLAG + "]");
        sayi("Usage: Deserializes an object into the current store overwriting the contents. Cf. serialize.");
        sayi("This replaces the object with the given index in the store.\n");
        sayi("If the -new flag is used, it is assumed that the object should be new. This means that if there is an existing object");
        sayi("with that identifier the operation will fail. If there is no identifier, one will be created.");
        sayi("Omitting the -new flag means that any object will be overwritten and if needed, a new identifier will be created");
        sayi("If the  " + UPDATE_FLAG + " or " + SHORT_UPDATE_FLAG + " is used, the existing object is simply updated");
        sayi("Note that an object cannot be new and updated at the same time.");
        say("See also: serialize, create_hash");
    }

    static final String BASE_32_FLAG = "-32";

    public void encode(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("encode [" + BASE_32_FLAG + "] arg");
            sayi("encode a string using base 64 or base 32. The default is base 64");
            sayi("Note: Enclose your argument in double quotes. You must escape embedded");
            sayi("      double quotes with \\\"");
            say("E.g.");
            sayi("clients>encode \"config \\\" foo \\\"\"\n" +
                    "  Y29uZmlnICIgZm9vICI\n" +
                    "  clients>decode Y29uZmlnICIgZm9vICI\n" +
                    "  config \" foo \"");
            say("note the embedded blanks and quotes are preserved.");
            return;
        }
        boolean doBase32 = inputLine.hasArg(BASE_32_FLAG);
        inputLine.removeSwitch(BASE_32_FLAG);
        // Do surgery so the line acts like the user expects.
        String originalLine = inputLine.getOriginalLine();
        originalLine = originalLine.substring("encode".length()).trim();
        if (doBase32) {
            originalLine = originalLine.substring(BASE_32_FLAG.length()).trim();
        }

        if (originalLine.length() == 0) {
            say("sorry, this needs a single argument.");
            return;
        }
        if (originalLine.startsWith("\"")) {
            originalLine = originalLine.substring(1);
        }
        if (originalLine.endsWith("\"")) {
            originalLine = originalLine.substring(0, originalLine.length() - 1);
        }
        String arg = originalLine.replace("\\\"", "\"");

        if (doBase32) {
            say(TokenUtils.b32EncodeToken(arg));
        } else {
            say(TokenUtils.b64EncodeToken(arg));
        }
    }

    public void decode(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("decode [" + BASE_32_FLAG + "] arg");
            sayi("decode a string using base 64 or base 32. The default is base 64");

            return;
        }
        boolean doBase32 = inputLine.hasArg(BASE_32_FLAG);
        inputLine.removeSwitch(BASE_32_FLAG);
        if (inputLine.getArgCount() != 1) {
            say("sorry, this needs a single argument.");
            return;
        }
        String arg = inputLine.getLastArg();
        if (doBase32) {
            say(TokenUtils.b32DecodeToken(arg));
        } else {
            say(TokenUtils.b64DecodeToken(arg));
        }
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
        for (String x : outputList) {
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
            List<String> keys = inputLine.getArgList(KEYS_FLAG);
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

    protected void showCommandLineSwitchesHelp() {
        sayi(LINE_LIST_COMMAND + " (optional) print the result in long format.");
        sayi(VERBOSE_COMMAND + " (optional) print the result in verbose format.");
        sayi(SEARCH_SIZE_FLAG + " (optional) print *only* the number of results.");
        sayi(SEARCH_RETURNED_ATTRIBUTES_FLAG + " [attr0,attr1,...] = return only those attributes. " +
                "Note you may specify long or verbose format too.");

    }

    protected void showSearchHelpExamples() {
        say("E.g.");
        sayi("search " + KEY_SHORTHAND_PREFIX + "approver " + " junit");
        say("Searches for the approver keys that are exactly 'junit'");
        say("E.g.");
        sayi("search " + KEY_SHORTHAND_PREFIX + "client_id " + SEARCH_REGEX_FLAG + " \".*07028.*\"");
        say("Searches for the client_id keys that contains '07028'");
        say("E.g.");
        sayi("search " + KEY_FLAG + " email " + SEARCH_SHORT_REGEX_FLAG + " \".*bigstate\\.edu.*\"");
        say("Searches the email keys that contain 'bigstate.edu'.");
        say("Note that the period must be escaped for a regex.");
        say("E.g.");
        sayi("search " + KEY_SHORTHAND_PREFIX + "client_id " +
                SEARCH_RETURNED_ATTRIBUTES_FLAG + " [name, email] " +
                SEARCH_SHORT_REGEX_FLAG + " " + ".*237.*");
        say("Searches the client_id keys that contain the string 237 and only print out the name and email from those.");
        say("E.g.");
        sayi("search " + SEARCH_DATE_FLAG + " creation_ts " + SEARCH_BEFORE_TS_FLAG + " 2021-01-02 " + SEARCH_RESULT_SET_NAME + " last_year");
        say("Searches the creation_ts keys as dates, returning all that are before Jan 2, 20201.");
        say("This also stores the result under the name last_year. See also the rs command help");
        say("E.g.");
        sayi("search " + KEY_SHORTHAND_PREFIX + "email " + SEARCH_SHORT_REGEX_FLAG + " \".*bigstate\\.edu.*\" " + SEARCH_DATE_FLAG + " creation_ts " + SEARCH_BEFORE_TS_FLAG + " 2021-01-02 " + SEARCH_RESULT_SET_NAME + " last_year_email");
        say("Searches per date as in the previous example and further restricts it to matching the given key.");
        say("This also stores the result under the name last_year_email. See also the rs command help");
        say("E.g. A date search");
        say("This searches by client id for clients created between the given dates. It stores the result");
        say("in the result set named 's234'");
        say("clients>search >client_id -r .*234.* -date creation_ts -after 2020-05-01 -before 2020-05-30 -rs s234");
        say("got 4 matches");
        say("\nSee also: rs");
    }


    //    static String SEARCH_LIST_KEYS_FLAG = "-listKeys";
    public static final String SEARCH_REGEX_FLAG = "-regex";
    public static final String SEARCH_SHORT_REGEX_FLAG = "-r";
    public static final String SEARCH_SIZE_FLAG = "-size";
    public static final String SEARCH_DEBUG_FLAG = "-debug";
    public static final String SEARCH_RETURNED_ATTRIBUTES_FLAG = "-out";
    public static final String SEARCH_RESULT_SET_NAME = "-rs";
    public static final String SEARCH_BEFORE_TS_FLAG = "-before";
    public static final String SEARCH_AFTER_TS_FLAG = "-after";
    public static final String SEARCH_DATE_FLAG = "-date";

    public HashMap<String, RSRecord> getResultSets() {
        return resultSets;
    }

    public void setResultSets(HashMap<String, RSRecord> resultSets) {
        this.resultSets = resultSets;
    }

    protected HashMap<String, RSRecord> resultSets = new HashMap<>();
    String tzOffset = null;

    /**
     * For dates. Allow users to supply ISO dates without a timezone and add in the current.
     * This computes it from the running JVM.
     *
     * @return
     */
    String getTzOffset() {
        if (tzOffset == null) {
            TimeZone tz = TimeZone.getDefault();

            tzOffset = (tz.getRawOffset() < 0) ? "-" : "+";
            int hr = Math.abs(tz.getRawOffset() / 1000 / 60 / 60);
            int min = Math.abs(tz.getRawOffset() / 1000 % 60);
            tzOffset = tzOffset + ((hr < 10 ? "0" : "") + hr) + ":" + ((min < 10 ? "0" : "") + min);
        }
        return tzOffset;
    }

    protected void showSearchHelp() {
        say("search ");
        sayi("[" + KEY_FLAG + " key | " + KEY_SHORTHAND_PREFIX + "key] ");
        sayi("[(" + SEARCH_REGEX_FLAG + "|" + SEARCH_SHORT_REGEX_FLAG + ") regex] ");
        sayi("[" + SEARCH_SIZE_FLAG + "] ");
        sayi("[" + SEARCH_DEBUG_FLAG + "] ");
        sayi("[" + LINE_LIST_COMMAND + " | " + VERBOSE_COMMAND + "]");
        sayi("[" + SEARCH_DATE_FLAG + " date_field (" + SEARCH_BEFORE_TS_FLAG + " time | " + SEARCH_AFTER_TS_FLAG + " time)] ");
        sayi("[" + SEARCH_RESULT_SET_NAME + " name] ");
        sayi("[" + SEARCH_RETURNED_ATTRIBUTES_FLAG + " list]");
        sayi("[condition]");
        say("----");
        sayi("Usage: Searches the current component for all entries satisfying the condition.");
        sayi("You may search either on a key, by date or both");
        sayi("The key search can be with a regular expression. Use the regex flag, other wise the last argument");
        sayi("[condition] will be matched exactly.");
        sayi("Note that condition is used if there is no regex specified. If there is a regex");
        sayi("specified as well, that takes precedence.");
        say("Search options");
        say("----");
        int w = 15; // field with for lh side
        String blanks = "                                                                   ";
        String link = " - ";
        blanks = blanks.substring(0, w + link.length()); // padding for any lines that run over
        say(StringUtils.RJustify(KEY_FLAG + " key | " + KEY_SHORTHAND_PREFIX + "key", w) + link + "the name of the key to be searched for");
        say(StringUtils.RJustify(SEARCH_REGEX_FLAG + "|" + SEARCH_SHORT_REGEX_FLAG + " regex", w) + link + "attempt to interpret regex as a regular expression");
        say(StringUtils.RJustify(SEARCH_RESULT_SET_NAME + " name", w) + link + "save the result as the name.");
        say(StringUtils.RJustify(SEARCH_DEBUG_FLAG, w) + link + "show stack traces. Only use this if you really need it.");
        say(StringUtils.RJustify(SEARCH_DATE_FLAG, w) + link + "search by date. You must have at least one time using either " + SEARCH_BEFORE_TS_FLAG + " or " + SEARCH_AFTER_TS_FLAG);
        say(blanks + "For date searches you may use either an ISO 8601 date in the form ");
        say(blanks + "YYYY-MM-DD or time, e.g. 2021-04-05T13:00:00Z");
        say(blanks + "would at 1 pm in UTC. If you do not supply a final Z or other timezone");
        say(blanks + "(+-HH:mm) then your current timezone is used.");
        say(blanks + "To search on a date range (i.e. between two times) specify both your");
        say(blanks + "before and after dates. Date searches are inclusive of the dates.");
        say("----");
        say("Other supported options");
        showCommandLineSwitchesHelp();
        showKeyShorthandHelp();
        sayi("If you want to see examples, invoke this with --ex.");
    }

    @Override
    public void search(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSearchHelp();
            if (inputLine.hasArg("--ex")) {
                say(""); // give it a break in wall of text
                showSearchHelpExamples();
            }
            return;
        } else {
            if (inputLine.hasArg("--ex")) {
                showSearchHelpExamples();
                return;
            }
        }

        boolean showStackTraces = inputLine.hasArg(SEARCH_DEBUG_FLAG);
        boolean storeRS = inputLine.hasArg(SEARCH_RESULT_SET_NAME);
        String rsName = null;
        if (storeRS) {
            rsName = inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME);
            inputLine.removeSwitchAndValue(SEARCH_RESULT_SET_NAME);
        }
        boolean hasDate = inputLine.hasArg(SEARCH_DATE_FLAG);
        String dateField = null;
        Date afterDate = null;
        Date beforeDate = null;
        if (hasDate) {
            dateField = inputLine.getNextArgFor(SEARCH_DATE_FLAG);
            inputLine.removeSwitchAndValue(SEARCH_DATE_FLAG);
            try {
                if (inputLine.hasArg(SEARCH_BEFORE_TS_FLAG)) {
                    beforeDate = getDateFromArg(inputLine, SEARCH_BEFORE_TS_FLAG);
                }
                if (inputLine.hasArg(SEARCH_AFTER_TS_FLAG)) {
                    afterDate = getDateFromArg(inputLine, SEARCH_AFTER_TS_FLAG);
                }
            } catch (ParseException pe) {
                say("Sorry, could not parse date: " + pe.getMessage());
                if (DebugUtil.isEnabled() || showStackTraces) {
                    pe.printStackTrace();
                }
                return;
            }

        }
        String key = getAndCheckKeyArg(inputLine);
        List<Identifiable> values = null;
        List<String> returnedAttributes = null;
        String condition = null;
        boolean isRegEx = false;
        boolean hasKey = key != null;
        if (hasKey) {
            if (inputLine.hasArg(SEARCH_RETURNED_ATTRIBUTES_FLAG)) {
                returnedAttributes = inputLine.getArgList(SEARCH_RETURNED_ATTRIBUTES_FLAG);
                inputLine.removeSwitchAndValue(SEARCH_RETURNED_ATTRIBUTES_FLAG);
            }
            condition = inputLine.getLastArg(); // default
            isRegEx = inputLine.hasArg(SEARCH_REGEX_FLAG) || inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG);
            if (isRegEx) {
                if (inputLine.hasArg(SEARCH_REGEX_FLAG)) {
                    condition = inputLine.getNextArgFor(SEARCH_REGEX_FLAG);
                    inputLine.removeSwitchAndValue(SEARCH_REGEX_FLAG);
                }
                if (inputLine.hasArg(SEARCH_SHORT_REGEX_FLAG)) {
                    condition = inputLine.getNextArgFor(SEARCH_SHORT_REGEX_FLAG);
                    inputLine.removeSwitchAndValue(SEARCH_SHORT_REGEX_FLAG);
                }
            }
        }
        try {
            if (hasKey) {
                if (hasDate) {
                    values = getStore().search(
                            key,
                            condition,
                            isRegEx,
                            returnedAttributes,
                            dateField,
                            beforeDate, afterDate);

                } else {
                    values = getStore().search(
                            key,
                            condition,
                            isRegEx,
                            returnedAttributes,
                            null,
                            null,
                            null);
                }
            } else {
                if (hasDate) {
                    values = getStore().search(
                            null,
                            null,
                            false,
                            returnedAttributes,
                            dateField,
                            beforeDate,
                            afterDate);

                } else {
                    // no query, do nothing.
                }
            }
            if (values == null) {
                String kk = getKeyArg(inputLine);
                say("No searchable criteria found." + ((kk == null) ? " No key or date." : " \"" + kk + "\" is not a valid key for this store."));
                return;
            }
            if (storeRS) {
                resultSets.put(rsName, new RSRecord(values, returnedAttributes));
                say("got " + values.size() + " match" + (values.size() == 1 ? "." : "es."));
                return;
            }
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
        if (printRS(inputLine, values, returnedAttributes, null)) return;
        say("\ngot " + values.size() + " match" + (values.size() == 1 ? "." : "es."));
    }

    // use clients
    // search -date creation_ts -after 2020-05-01 -before 2020-05-30 -rs s2
    // search >client_id -r .*234.* -date creation_ts -after 2020-05-01 -before 2020-05-30 -rs s234
    // search >client_id -r .*234.* -rs all-234
    private Date getDateFromArg(InputLine inputLine, String arg) throws ParseException {
        String computedDateString = inputLine.getNextArgFor(arg);
        if(computedDateString.equals("now")){
            return new Date();
        }
        inputLine.removeSwitchAndValue(arg);
        if (-1 == computedDateString.indexOf("T")) {
            // then there is no time, just a date. Convert to ISO
            computedDateString = computedDateString + "T00:00:00" + getTzOffset();
        }
        try {
            return Iso8601.string2Date(computedDateString).getTime();
        } catch (ParseException pe) {
            computedDateString = computedDateString + getTzOffset();
            // try it again in case they are going local
            try {
                return Iso8601.string2Date(computedDateString).getTime();
            } catch (ParseException e) {
                throw e;
            }

        }
    }

    /**
     * If limits is empty or null, show everything. If limits has an element, that is the number of things to show
     * starting at 0. If it has two elements, the zeroth is the start, the 1st is that stop index.
     *
     * @param inputLine
     * @param values
     * @param returnedAttributes
     * @param limits
     * @return
     */
    public boolean printRS(InputLine inputLine, List<Identifiable> values, List<String> returnedAttributes, List<Integer> limits) {
        if (values.isEmpty()) {
            say("no matches");
            return true;
        }
        if (inputLine.hasArg(SEARCH_SIZE_FLAG)) {
            say("Got " + values.size() + " results");
            return true;
        }
        int start = 0;
        int stop = values.size();
        if (limits != null && !limits.isEmpty()) {
            if (limits.size() == 1) {
                stop = Math.min(values.size(), limits.get(0));
            } else {
                start = Math.max(0, limits.get(0));
                stop = Math.min(values.size(), limits.get(1));
            }
        }
        boolean longFormat = inputLine.hasArg(VERBOSE_COMMAND) || inputLine.hasArg(LINE_LIST_COMMAND);
        for (int i = start; i < stop; i++) {
            Identifiable identifiable = values.get(i);
            if (longFormat) {
                longFormat(identifiable, returnedAttributes, inputLine.hasArg(VERBOSE_COMMAND));
                if (1 < values.size()) {
                    say("-----"); // or the output runs together
                }
            } else {
                say(format(identifiable));
            }
        }
        return false;
    }

    public static class RSRecord {
        public RSRecord(List<Identifiable> rs, List<String> fields) {
            this.rs = rs;
            this.fields = fields;
        }

        public List<Identifiable> rs;
        public List<String> fields;
    }

    @Override
    protected void showLSHelp() {
        say("ls [" + LINE_LIST_COMMAND + "  | " + VERBOSE_COMMAND + " | " + ALL_LIST_COMMAND + "] | [" + KEY_FLAG + " key | " + KEYS_FLAG + " array] id");
        sayi("Usage: Lists information about the contents of the store, an entry and");
        sayi("   individual values of the entry.");
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
        sayi("\nSee also list_keys, search, archive");
    }

    @Override
    protected void showRMHelp() {
        say("rm [" + KEY_FLAG + " | " + KEYS_FLAG + " list] id");
        sayi("Usage: Remove a property from this the object with the given value.");
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
        if (inputLine.hasArg(SEARCH_RESULT_SET_NAME)) {
            RSRecord rsRecord = resultSets.get(inputLine.getNextArgFor(SEARCH_RESULT_SET_NAME));
            if (rsRecord == null) {
                say("no such stored result.");
                return;
            }

            return;
        }
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("Object not found");
            return;
        }
        String key = getAndCheckKeyArg(inputLine);
        // if the request does not have new stuff, do old stuff.
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            super.rm(inputLine);
            rmCleanup(identifiable);
            return;
        }
        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> array = inputLine.getArgList(KEYS_FLAG);

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
        String key = getAndCheckKeyArg(inputLine);
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            super.ls(inputLine);
            return;
        }
        if (inputLine.hasArg(KEYS_FLAG)) {
            List<String> array = inputLine.getArgList(KEYS_FLAG);

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
                "[" + KEYS_FLAG + " array] [id | index]");
        sayi("Usage: Update the properties of the object.");
        sayi("This has three modes. Just an id will prompt you for every value to update.");
        sayi("Alternately, you may either specify a single key + value OR you may specify an array of keys");
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
        sayi("A few notes.");
        sayi("1. If the value of the property is a JSON object, you can edit it.");
        sayi("2. If the value of the property is an array, then you may add a value, delete a value,");
        sayi("   replace the entire contents (new entries are comma separated) or simply clear the .");
        sayi("   entire list of entries. You may also back out of the update request.");
        sayi("3. What you type in is stored without change, so if you need to save the hash of something,");
        sayi("    e.g. a password, use create_hash to make the hash first and save that.");
        sayi("See also: list_keys, create_hash");
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
        String key = getAndCheckKeyArg(inputLine);
        if (key == null && !inputLine.hasArg(KEYS_FLAG)) {
            say("sorry, but that is not a recognized key.");
            return;
        }
        if (key == null && inputLine.hasArg(KEYS_FLAG)) {
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
            List<String> keys = inputLine.getArgList(KEYS_FLAG);
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
        /* Editing QDL scripts this way is a PITA. Just skip it. Needs refactored
        boolean loadQDL = getInput("Load only a QDL script or edit the full config? (q/f)", "f").equalsIgnoreCase("q");
                if (loadQDL) {
                    JSONObject oldCfg = (JSONObject) json;
                    JSONObject qdlcfg = loadQDLScript(oldCfg);

                    if (qdlcfg == null) {
                        return false;
                    } // they cancelled out of it

                    map.put(key, oldCfg.toString());
                    return true;
                } else {*/
                JSONObject newConfig = (JSONObject) inputJSON((JSONObject) json, "client configuration");
                if (newConfig == null) {
                    return false;
                } // user cancelled
                map.put(key, newConfig);
                return true;
                //}
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
            showListKeysHelp(inputLine);
            return;
        }
        XMLConverter xmlConverter = getStore().getXMLConverter();
        String primaryKey = null;
        if (xmlConverter instanceof MapConverter) {
            primaryKey = ((MapConverter) xmlConverter).getKeys().identifier();
        }
        if (xmlConverter instanceof MapConverter) {
            MapConverter mc = (MapConverter) xmlConverter;
            ArrayList<String> kk = new ArrayList<>();
            kk.addAll(mc.getKeys().allKeys());
            if (primaryKey != null) {
                for (int i = 0; i < kk.size(); i++) {
                    if (kk.get(i).equals(primaryKey)) {
                        kk.remove(i);
                        kk.set(i, primaryKey + "*");
                        break;
                    }
                }
            }
            // print them in order.
            FormatUtil.formatList(inputLine, kk);
        }
    }

    protected void showListKeysHelp(InputLine inputLine) {
        say("list_keys");
        sayi("Usage: This lists the keys of the current store.");
        sayi("The primary key will have a '*' added to the end of it");
        FormatUtil.printFormatListHelp(getIoInterface(), INDENT, inputLine);
    }

    EditorEntry editorEntry = null;

    public EditorEntry getEditorEntry() {
        if (editorEntry == null) {
            editorEntry = new EditorEntry();
            editorEntry.exec = "vim";
            editorEntry.name = "vim";
        }
        return editorEntry;
    }

    String TEMP_FILE = "/opt/cilogon-oa2/var/temp";
    File tempDir = null;

    protected File getTempDir() {
        if (tempDir == null) {
            tempDir = new File(TEMP_FILE);
            if (tempDir.exists()) {
                if (!tempDir.isDirectory()) {
                    say("sorry, but could not find the temp directory");
                }
            } else {
                tempDir.mkdirs();
            }
        }
        return tempDir;
    }

    @Override
    public void edit(InputLine inputLine) {
        if (showHelp(inputLine)) {
            say("edit [id | index]");
            sayi("Usage: Edit an object in an external editor.");
            sayi("Note that this will update the object on exiting the editor");
        }
        File tempFile;
        try {
            tempFile = File.createTempFile("edit", ".oa2", getTempDir());
        } catch (IOException iox) {
            if (DebugUtil.isEnabled()) {
                iox.printStackTrace();
            }
            say("could not open file:" + iox.getMessage());
            return;
        }
        Identifiable x = findItem(inputLine);
        XMLMap c = new XMLMap();
        getStore().getXMLConverter().toMap(x, c);
        try {
            FileOutputStream fos = new FileOutputStream(tempFile);
            c.toXML(fos);
            fos.flush();
            fos.close();
        } catch (IOException iox) {
            if (DebugUtil.isEnabled()) {
                iox.printStackTrace();
            }

            say("could not write temp file:" + iox.getMessage());
            return;
        }
        if (EditorUtils.EDITOR_RC_OK == EditorUtils.editFile(getEditorEntry(), tempFile)) {
            try {
                FileInputStream fis = new FileInputStream(tempFile);
                c = new XMLMap();

                c.fromXML(fis);
                fis.close();
                Identifiable identifiable = getStore().getXMLConverter().fromMap(c, null);
                if (!identifiable.getIdentifier().equals(x.getIdentifier())
                ) {
                    boolean ok = readline("You realize that the identifier for the original and edited objects are not the same, right? Save anyway(y/n)?").equals("y");
                    if (ok) {
                        getStore().save(identifiable);

                    } else {
                        say("save aborted");
                        return;
                    }

                }
                getStore().save(identifiable);

            } catch (IOException iox) {
                if (DebugUtil.isEnabled()) {
                    iox.printStackTrace();
                }
                say("there was a problem reading the edited file:" + iox.getMessage());
            }
        }
        say("update ok.");
    }

    protected void oldEdit(InputLine inputLine) {
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


        if (inputLine.hasArg(ARCHIVE_RESTORE_FLAG)) {
            String rawID = inputLine.getLastArg();
            if (rawID.startsWith("/")) {
                rawID = rawID.substring(1);
            }
              String rawTargetVersion = inputLine.getNextArgFor(ARCHIVE_RESTORE_FLAG);

             boolean doLatest = rawTargetVersion.equals(ARCHIVE_LATEST_VERSION_ARG);
             long targetVersion = 0;
            //DoubleHashMap<URI, Long> versionNumbers = getVersions(rawID);

            if (doLatest) {
                targetVersion = -1L;
            } else {
                try {
                    targetVersion = Long.parseLong(rawTargetVersion);
                } catch (NumberFormatException nfx) {
                    say("sorry, but \"" + rawTargetVersion + "\" could not be parsed as a version number");
                    return;
                }
            }
             Identifiable identifiable = findItem(inputLine);
            if(identifiable == null){
                say("sorry, no such object");
                return;
            }
            Identifiable storedVersion= getStoreArchiver().getVersion(identifiable.getIdentifier(), targetVersion );
            if(storedVersion == null){
                say("sorry, but the version you requested for id \"" + rawID  + "\" does not exist.");
            }
            if (getInput("Are you sure that you want to replace the current version with version \"" + (targetVersion==-1?"latest":targetVersion) + "\"?(y/n)", "n").equals("y")) {
                // TODO Maybe put some version information inside the object?????
                // Practical problem is that there is no place to necessarily put it in the general case.
                // So version number, timestamp for version?
                // What to do with these if the version is restored?
                storedVersion.setIdentifier(identifiable.getIdentifier());
                getStore().save(storedVersion);
                say("done! Note: you may have to e.g. approve this again if it is a client.");
                return;
            } else {
                say("aborted.");
            }
            return;
        }
        Identifiable identifiable = findItem(inputLine);


        /*
                Contract is that identifiers never have fragments -- these are used by the system for information.
                In this case, a fragment of the form version_x where x is a non-negative integer is added.
                 */
        if (inputLine.hasArg(ARCHIVE_VERSIONS_FLAG)) {
            TreeMap<Long, Identifiable> sortedMap = getStoreArchiver().getVersionsMap(identifiable);
            if (sortedMap == null) return;
            for (Long index : sortedMap.keySet()) {
                say(archiveFormat(sortedMap.get(index)));
            }
            return;
        }

        if (isShow) {
            Identifiable target = showVersion(inputLine, showArg, identifiable);
            if (target == null) return;
            longFormat(target, true); // show everything!
            return;
        }
        // If we are at this point, then the user wants to version the object
        if(identifiable == null){
            // they supplied non-existent id
            say("object not found.");
            return;
        }
        DoubleHashMap<URI, Long> versionNumbers = getStoreArchiver().getVersions(identifiable.getIdentifier());
        long newIndex =0L; // for first version if none found
        if(versionNumbers!= null && !versionNumbers.isEmpty()){
            newIndex = getStoreArchiver().getLatestVersionNumber(versionNumbers) + 1;
        }
        // archive /testScheme:oa4md,2018:/client_id/f25ffda14af7100284c0234c8fb836a
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

        MapConverter mc = getMapConverter();

        mc.toMap(identifiable, map);

        mc.fromMap(map, newVersion);

        Identifier newID = getStoreArchiver().createVersionedID(identifiable.getIdentifier(), newIndex);
        newVersion.setIdentifier(newID);
        getStore().save(newVersion);


    }

    private Identifiable showVersion(InputLine inputLine, String showArg, Identifiable identifiable) {
        long targetVersion = -1L;
        URI uri = null;
        String rawID = null;
        if (inputLine.getArgCount() == 0) {
            if (!hasID()) {
                say("sorry, no id found. Either set it with set_id or supply it as the final argument");
                return null;
            }
            rawID = getID().toString();
        } else {
            // possibly an argument that is the id.
            // Supplying a final argument over-rides the id.
            rawID = inputLine.getLastArg();

            if (rawID.startsWith("/")) {
                rawID = rawID.substring(1);
            }
            try {
                uri = URI.create(rawID);
            } catch (Throwable urx) {
                // no argument, no set id.
                if (!hasID()) {
                    say("sorry, no id found. Either set it with set_id or supply it as the final argument");
                    return null;
                }
            }

        }
        String ss = (uri == null) ? null : uri.getSchemeSpecificPart();
        if (StringUtils.isTrivial(ss)) {
            if (!hasID()) {
                say("sorry, no id found. Either set it with set_id or supply it as the final argument");
                return null;
            }

        }

        DoubleHashMap<URI, Long> versionNumbers = getStoreArchiver().getVersions(identifiable.getIdentifier());
        if (showArg.equalsIgnoreCase(ARCHIVE_LATEST_VERSION_ARG)) {
            targetVersion = getStoreArchiver().getLatestVersionNumber(versionNumbers);
        } else {
            try {
                targetVersion = Long.parseLong(showArg);
            } catch (NumberFormatException nfx) {
                say("sorry but the version number you supplied \"" + targetVersion + "\" is not a number.");
                return null;
            }
        }
        if (versionNumbers.getByValue(targetVersion) == null) {
            say("sorry, but " + targetVersion + " is not the number of a version for \"" + identifiable.getIdentifierString() + "\".");
            return null;
        }
        Identifiable target = (Identifiable) getStore().get(BasicIdentifier.newID(versionNumbers.getByValue(targetVersion)));
        return target;
    }


    String ARCHIVE_VERSIONS_FLAG = "-versions";
    String ARCHIVE_RESTORE_FLAG = "-restore";
    String ARCHIVE_SHOW_FLAG = "-show";
    String ARCHIVE_LATEST_VERSION_ARG = "latest";


    String[] regexSpeciaChars = new String[]{".", "^", "$", "*", "+", "-", "?", "(", ")", "[", "]", "{", "}", "\\", "|", "—", "/",};

    protected String escapeRegex(String x) {
        String y = x;
        for (int i = 0; i < regexSpeciaChars.length; i++) {
            y = y.replace(regexSpeciaChars[i], "\\" + regexSpeciaChars[i]);
        }
        return y;
    }

    protected void showArchiveHelp() {
        say("archive [-versions] | [-restore version] | [-show] [id] - archive an object");
        say("Usage: This will either create a copy of the current version");
        sayi("   or restore a versioned object.");
        sayi("archive [id] - version the object, assigning it the last version.");
        sayi("archive -versions [id]  - list the versions of an object");
        sayi("archive -latest - show the number of the latest version (-1 if no versions exist)");

        sayi("archive -restore (number | latest) [id] - restore the given version");
        sayi("of this. If a number is given, use that. If the word \"latest\" (no quotes)");
        sayi("is used, give back the latest version.");
        sayi(ARCHIVE_SHOW_FLAG + " (number | latest) - show the given version. You may also use the word \"latest\"");
        sayi("    to get the latest version.");
        sayi("Note that archive version numbers increase, so the highest number is the most recent.");
    }

    protected String archiveFormat(Identifiable id) {
        return format(id);
    }

    public void copy(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showCopyHelp();
            return;
        }
        boolean forceIt = inputLine.hasArg(FORCE_COPY_FLAG);
        boolean randomID = inputLine.hasArg(RANDOM_ID_FLAG);
        inputLine.removeSwitch(FORCE_COPY_FLAG);
        inputLine.removeSwitch(RANDOM_ID_FLAG);

        String sourceString = inputLine.getArg(1); // zero-th arg is name of command.
        String targetString = null;
        if (inputLine.getArgCount() == 2) {
            targetString = inputLine.getArg(2);
        }
        Identifier sourceId = null;
        Identifier targetId = null;
        try {
            sourceId = BasicIdentifier.newID(sourceString);
        } catch (Throwable t) {
            say("sorry, but the first argument \"" + sourceString + "\" is not a valid identifier");
            return;
        }
        if (isTrivial(targetString)) {
            if (!randomID) {
                say("No id specified and you did not supply the " + RANDOM_ID_FLAG + " flag. Cannot process.");
                return;
            }
        } else {
            try {
                targetId = BasicIdentifier.newID(targetString);
            } catch (Throwable t) {
                say("sorry, but the second argument \"" + targetString + "\" is not a valid identifier");
                return;
            }
        }

        Identifiable source = (Identifiable) getStore().get(sourceId);
        // store is charged with making a valid, unused random id, so no need to check if that is requested.
        if (!forceIt && !randomID && getStore().containsKey(targetId)) {
            say("sorry, but \"" + targetId + "\" already exists. Consider using the " + FORCE_COPY_FLAG + " flag if you need to overwrite it.");
            return;
        }

        Identifier newID = doCopy(source, targetId, randomID);
        if (randomID) {
            say("new copy with id \"" + newID.toString() + "\" created.");
        }
    }

    /**
     * Do the copy. Note that if useRandomID is true, targetID is ignored,
     *
     * @param source
     * @param targetId
     * @param useRandomID
     */
    protected Identifier doCopy(Identifiable source, Identifier targetId, boolean useRandomID) {
        MapConverter mc = getMapConverter();
        Identifiable newVersion = getStore().create();
        Identifier newVersionIdentifier = newVersion.getIdentifier();
        XMLMap map = new XMLMap();
        mc.toMap(source, map);

        mc.fromMap(map, newVersion);
        // Caveat: this copy will set the target id equal to the source if
        if (useRandomID) {
            newVersion.setIdentifier(newVersionIdentifier);
        } else {
            newVersion.setIdentifier(targetId);
        }
        getStore().save(newVersion);
        if (useRandomID) {
            return newVersionIdentifier;
        } else {
            return targetId;
        }
    }

    private void showCopyHelp() {
        say("copy source target [" + FORCE_COPY_FLAG + "] [" + RANDOM_ID_FLAG + "] [new_id]");
        sayi("Usage: Copy source to target");
        sayi(FORCE_COPY_FLAG + " - force it, so overwrite if the target exists.");
        sayi(RANDOM_ID_FLAG + " - create a random id for the target.");
        sayi("new_id - specify the new id. Note if this is present, " + RANDOM_ID_FLAG + " is ignored.");
        sayi("This will create a complete copy of source and store it with the id of target.");
        sayi("Note: This will refuse to do this if target exists.");
        sayi("Note: If you do not specify to use a random id and do not supply one, this will abort.");
        sayi("This only makes a simple copy. Except if this is a client, and the approval will be cloned too, though not permissions etc.");
        sayi("Other objects may need to be updated (such as permissions).");
        sayi("Note: source and target are identifiers (no lead /).");
        sayi("E.g. In the client store:\n");
        sayi("  client>copy dev:command.line dev:no_cfg\n");
        sayi("would take the client configuration with id dev:command.line and create a new client config. that is");
        sayi("identical except with id dev:no_cfg. In this case, as a new client, it needs to be approved.");
        say("E.g.");
        sayi("  client>copy dev:command.line " + RANDOM_ID_FLAG + "\n");
        sayi("Creates a copy of dev:command.line with a random id, which is printed");

    }

    public static String KEY_SHORTHAND_PREFIX = ">";
    public static String RANDOM_ID_FLAG = "-random_id";
    public static String FORCE_COPY_FLAG = "-f";

    /**
     * resolves key shorthand of >key_name or -key key_name
     * returns null if no such key OR if it is not valid in the
     * key list.
     *
     * @param inputLine
     * @return
     */
    protected String getAndCheckKeyArg(InputLine inputLine) {
        String keyArg = getKeyArg(inputLine);
        if (keyArg == null) {
            return null;
        }

        if (getMapConverter().getKeys().allKeys().contains(keyArg)) {
            return keyArg;
        }
        return null;
    }

    protected String getKeyArg(InputLine inputLine) {
        return getKeyArg(inputLine, false);
    }

    /**
     * Just gets the key argument or null if not present. This does no checking if
     * the key that is found is valid for the store.
     *
     * @param inputLine
     * @param removeIt
     * @return
     */
    protected String getKeyArg(InputLine inputLine, boolean removeIt) {
        if (inputLine.size() <= 1) {
            // so no actual arguments supplied.
            return null;
        }
        if (inputLine.hasArg(KEY_FLAG)) {
            String k = inputLine.getNextArgFor(KEY_FLAG);
            if (removeIt) {
                inputLine.removeSwitchAndValue(KEYS_FLAG);
            }
            return k;
        }

        // have to search
        for (int i = 1; i < inputLine.size(); i++) {
            String arg = inputLine.getArg(i);
            if (arg.startsWith(KEY_SHORTHAND_PREFIX)) {
                String k = arg.substring(1);
                if (removeIt) {
                    inputLine.removeSwitchAndValue(arg);
                }
                return k;
            }
        }
        return null;
    }

    protected void showKeyShorthandHelp() {
        sayi("Note: The argument idiom '-key key_name' may be replaced with '" + KEY_SHORTHAND_PREFIX + "key_name' as a shorthand");
    }

    public void rename(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("rename source_id target_id");
            sayi("Usage: Rename source_id to target_id, replacing it.");
            say("E.g.\n");
            sayi("rename dev:test dev:test/no_cfg\n");
            sayi("(Note lead slashes on ids are optional) would rename dev:test to dev:test/no_cfg");
            sayi("At the end of this operation, dev:test would not exist. ");
            sayi("See also: copy, rm");
            return;
        }
        if (inputLine.getArgCount() != 2) {
            say("Sorry, you must supply both a source id and a target id");
            return;
        }
        String src = inputLine.getArg(1);
        if (src.startsWith("/")) {
            src = src.substring(1);
        }
        if (isTrivial(src)) {
            say("Sorry, but you must supply a valid source id");
            return;
        }
        Identifier srcID;
        try {
            srcID = BasicIdentifier.newID(src);
        } catch (Throwable t) {
            say("Sorry, but the source id \"" + src + "\" you supplied is not a valid id");
            return;
        }
        if (!getStore().containsKey(srcID)) {
            say("Sorry, but the source is not in this store.");
            return;
        }

        String target = inputLine.getArg(2);
        if (target.startsWith("/")) {
            target = target.substring(1);
        }
        if (isTrivial(target)) {
            say("Sorry, but you must supply a valid target id");
            return;
        }
        Identifier targetID;
        try {
            targetID = BasicIdentifier.newID(target);
        } catch (Throwable t) {
            say("Sorry, but the target id \"" + target + "\" you supplied is not a valid id");
            return;
        }
        if (getStore().containsKey(targetID)) {
            say("Sorry, but " + targetID.toString() + " already exists on this system.");
            return;
        }
        doRename(srcID, targetID);
    }

    protected void doRename(Identifier srcID, Identifier targetID) {
        Identifiable source = (Identifiable) getStore().get(srcID);
        doCopy(source, targetID, false);  // always require an explicit id for the rename.
        getStore().remove(srcID);
    }

    public void rs(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showResultSetHelp();
            return;
        }
        if (inputLine.hasArg(RS_SHOW_KEY)) {
            String name = inputLine.getLastArg();
            inputLine.removeArgAt(inputLine.getArgCount());
            int count = -1;
            List<Integer> limits = new ArrayList<>();
            if (inputLine.getArgCount() > 1) {
                List<String> argsList = inputLine.getArgList(RS_SHOW_KEY);
                if (argsList.isEmpty()) {
                    limits.add(inputLine.getNextIntArg(RS_SHOW_KEY));
                } else {
                    for (String x : argsList) {
                        try {
                            limits.add(Integer.parseInt(x));
                        } catch (Throwable nfx) {
                            limits = null;
                            break; // end the loop, no usable integers
                        }
                    }
                }
            }
            inputLine.removeSwitchAndValue(RS_SHOW_KEY);
            List<String> requestedKeys = null;
            if (inputLine.hasArg(SEARCH_RETURNED_ATTRIBUTES_FLAG)) {
                requestedKeys = inputLine.getArgList(SEARCH_RETURNED_ATTRIBUTES_FLAG); // might be empty
                inputLine.removeSwitchAndValue(SEARCH_RETURNED_ATTRIBUTES_FLAG);
            }
            if (!resultSets.containsKey(name)) {
                say("result set named \"" + name + "\" not found");
                return;
            }
            List<String> foundKeys = resultSets.get(name).fields;
            if (requestedKeys != null && !requestedKeys.isEmpty()) {
                if (foundKeys == null) {
                    foundKeys = requestedKeys;
                } else {
                    // Get the intersection of the lists. Only print what is actually there.
                    Set<String> result = foundKeys.stream()
                            .distinct()
                            .filter(requestedKeys::contains)
                            .collect(Collectors.toSet());
                    foundKeys = new ArrayList<>();
                    foundKeys.addAll(result);
                }
            }
            printRS(inputLine, resultSets.get(name).rs, foundKeys, limits);
            return;
        }
        if (inputLine.hasArg(RS_CLEAR_KEY)) {
            resultSets = new HashMap<>();
            say("all results cleared");
            return;
        }
        if (inputLine.hasArg(RS_REMOVE_KEY)) {
            inputLine.removeSwitch(RS_REMOVE_KEY);
            String name = inputLine.getLastArg();
            resultSets.remove(name);
            say("result set named \"" + name + "\" has been removed");
            return;
        }
        if (inputLine.hasArg(RS_LIST_KEY)) {
            if (resultSets.isEmpty()) {
                return;
            }
            for (String key : resultSets.keySet()) {
                String out = key + ": " + resultSets.get(key).rs.size() + " entries";
                if (resultSets.get(key).fields != null) {
                    out = out + ",  fields=" + resultSets.get(key).fields;
                }
                // Someday use this: StringUtils.formatMap()
                // This however gets messy for clients where there are client approvals.
                say(out);
            }
            return;
        }
    }

    public static String RS_SHOW_KEY = "-show";
    public static String RS_REMOVE_KEY = "-rm";
    public static String RS_CLEAR_KEY = "-clear";
    public static String RS_LIST_KEY = "-list";

    protected void showResultSetHelp() {
        sayi("rs flags [rs_name].");
        sayi("Result set management. All of these except " + RS_CLEAR_KEY + " have the name of the result");
        sayi("set as the last argument.");
        sayi("If you save a result set using the " + SEARCH_RESULT_SET_NAME + " flag in the search");
        sayi("command, you can display it, here or remove it.");
        sayi("Other commands will allow for using the result set ");
        sayi(RS_REMOVE_KEY + " remove the stored result set. This does not touch the entries.");
        sayi(RS_LIST_KEY + " list store results sets");
        sayi(RS_CLEAR_KEY + " clear all stored result sets.");
        sayi(RS_SHOW_KEY + " show the given result set. You may give an integer to show that number, a list of ");
        sayi("   two integers for the start and stop limits, or no value which shows the entire set.");
        sayi("The following switches are supported for the " + RS_SHOW_KEY + " command:");
        showCommandLineSwitchesHelp();
    }

    public StoreArchiver getStoreArchiver() {
        if(storeArchiver == null){
            storeArchiver = new StoreArchiver(getStore());
        }
        return storeArchiver;
    }

    StoreArchiver storeArchiver;
}
