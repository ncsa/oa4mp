package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.CommandLineTokenizer;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.LineEditor;
import edu.uiuc.ncsa.security.util.cli.StoreCommands;
import net.sf.json.JSONObject;

import java.io.*;
import java.util.List;
import java.util.Vector;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization and searching
 * <p>Created by Jeff Gaynor<br>
 * on 7/2/18 at  10:06 AM
 */
public abstract class StoreCommands2 extends StoreCommands {
    public StoreCommands2(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public StoreCommands2(MyLoggingFacade logger, Store store) {
        super(logger, store);
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
        if (inputLine.hasArg("-file")) {
            try {
                is = new FileInputStream(inputLine.getNextArgFor("-file"));

                XMLMap map = new XMLMap();
                map.fromXML(is);
                is.close();
                Identifiable x = getStore().getXMLConverter().fromMap(map, null);
                if (isNew) {
                    if (getStore().containsKey(x.getIdentifier())) {
                        say("Error! The object with identifier \"" + x.getIdentifierString() + "\" already exists and you specified the item was new. Aborting.");
                        return;
                    }
                } else {
                    if (x.getIdentifier() == null) {
                        //handles the case where this is new and needs an identifier created. Only way to get
                        // a new unused identifier reliably is to have the store create a new entry then we update that.
                        Identifiable c = getStore().create();
                        x.setIdentifier(c.getIdentifier());
                        say("Created identifier \"" + c.getIdentifierString() + "\".");
                    }
                    // second case, overwrite whatever.
                    getStore().save(x);
                }
                say("done!");
            } catch (Throwable e) {
                say("warning, load file at path \"" + inputLine.getNextArgFor("-file") + "\": " + e.getMessage());
            }
        } else {
            say("Missing file argument. Cannot deserialize.");
            return;
        }

    }

    @Override
    public void serialize(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showSerializeHelp();
            return;
        }
        Identifiable x = findItem(inputLine);
        if (x == null) {
            say("Object not found");
            return;
        }
        XMLMap c = new XMLMap();
        getStore().getXMLConverter().toMap(x, c);
        OutputStream os = System.out;
        boolean hasFile = false;
        if (inputLine.hasArg("-file")) {
            try {
                os = new FileOutputStream(inputLine.getNextArgFor("-file"));
                hasFile = true;
            } catch (FileNotFoundException e) {
                say("warning, could not find file in argument \"" + inputLine.getNextArgFor("-file"));
            }
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
        say("search -key key [-regex|-la -size] [-listKeys] condition");
        sayi("Searches the current component for all entries satisfying the condition. You may also specify that the ");
        sayi("condition is a regular expression rather than using simple equality");
        sayi("Invoking this with the -listkeys flag prints out all the keys for this store. Omit that for searches.");
        sayi("-key = the name of the key to be searched for");
        sayi("-regex (optional) attempt to interpret the conditional as a regular expression");
        sayi("-la (optional) print the result in long format.");
        sayi("-size (optional) print *only* the number of results.");
        sayi("\nE.g.\n");
        sayi("search -key client_id -regex \".*07028.*\"");
        sayi("\n(In the clients components) This would find the clients whose identifiers contain the string 07028");
        sayi("\nE.g.\n");
        sayi("search -key email -regex \".*bigstate\\.edu.*\"");
        sayi("\n(in the clients or user component) This would match all email addresses from that institution bigstate.edu. \n");
        sayi("Note that the period must be escaped for a regex.");

    }


    @Override
    public void search(InputLine inputLine) {
        String KEY_FLAG = "-key";
        String LIST_KEYS_FLAG = "-listKeys";
        String REGEX_FLAG = "-regex";
        String LONG_LIST_FLAG = "-la";
        String SIZE_FLAG = "-size";
        if (showHelp(inputLine)) {
            showSearchHelp();
            return;
        }
        SerializationKeys keys = ((MapConverter) getStore().getXMLConverter()).getKeys();

        if (inputLine.hasArg(LIST_KEYS_FLAG)) {
            if (getStore().getXMLConverter() instanceof MapConverter) {
                say("keys");
                say("-------");
                for (String key : keys.allKeys()) {
                    say(key);
                }
            }
            return;
        }

        if (inputLine.hasArg(KEY_FLAG)) {
            String key = inputLine.getNextArgFor(KEY_FLAG);
            if (!keys.allKeys().contains(key)) {
                say("Sorry, but the key \"" + key + "\" is not a known key for this component.");
                return;
            }
            List<Identifiable> values = null;
            try {
                values = getStore().search(key, inputLine.getLastArg(), inputLine.hasArg(REGEX_FLAG));
            } catch (Throwable t) {
                say("Sorry, that didn't work:" + t.getMessage());
                return;
            }
            if (values.isEmpty()) {
                say("no matches");
            }
            if (inputLine.hasArg(SIZE_FLAG)) {
                say("Got " + values.size() + " results");
                return;
            }
            for (Identifiable identifiable : values) {
                if (inputLine.hasArg(LONG_LIST_FLAG)) {
                    longFormat(identifiable);
                } else {
                    say(format(identifiable));
                }
            }
            say("\ngot " + values.size() + " match" + (values.size() == 1 ? "." : "es."));
        } else {
            say("Sorry, you must specify a key for the search. Try typing \nsearch " + LIST_KEYS_FLAG + "\n for all available keys");
        }

    }

    @Override
    protected void showUpdateHelp() {
        say("update [" + UPDATE_ADD_FLAG + " | " + UPDATE_REMOVE_FLAG + " -remove ] " +
                "[" + UPDATE_KEY_FLAG + " key "+ UPDATE_VALUE_FLAG + " value | " +
                UPDATE_JSON_FLAG + " value] index\n");
        sayi("where the index is the index in the list command.");
        sayi("Optionally you may set a specific value for a key within the object. ");
        sayi("You may also specify that, if the value is a list, to simply add to its list");
        sayi("E.g.");
        sayi("update " + UPDATE_REMOVE_FLAG + " " + UPDATE_KEY_FLAG + " lifetime /foo:bar");
        sayi("would find the object with id foo:bar and remove the value of the key 'lifetime'");
        sayi("E.g.");
        sayi("update " + UPDATE_ADD_FLAG + " " +  UPDATE_JSON_FLAG + " '{\"fnord\":[\"blarf0\",\"blarf1\"]}' /foo:bar");
        sayi("(Note the single quotes around the raw JSON)");
        sayi("This would add the given entries to the array named fnord");
        sayi("Generally JSON is a better way to set multiple values, since the other method is simply ");
        sayi("a way to set an individual value. ");
        sayi("E.g.");
        sayi("update  " + UPDATE_JSON_FLAG + " '{\"fnord\":[\"blarf0\",\"blarf1\"]}' /foo:bar");
        sayi("In this case, without the " + UPDATE_ADD_FLAG + ", the values for the array named fnord would be replaced.");
        sayi("Any existing values would be lost.");
        say("See also list_keys");
    }

    String UPDATE_ADD_FLAG = "-add";
    String UPDATE_REMOVE_FLAG = "-remove";
    String UPDATE_KEY_FLAG = "-key";
    String UPDATE_VALUE_FLAG = "-value";
    String UPDATE_JSON_FLAG = "-json";

    @Override
    public void update(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showUpdateHelp();
            return;
        }
        if (inputLine.size() == 2) { // line is [func_name, arg0, arg1, ...] so this means a single argument. Assume its an index.
            super.update(inputLine);
            return;
        }
        // new stuff. The assumption is that the user is trying to update something.
        boolean addFlag = inputLine.hasArg(UPDATE_ADD_FLAG);
        boolean removeFlag = inputLine.hasArg(UPDATE_REMOVE_FLAG);
        boolean jsonFlag = inputLine.hasArg(UPDATE_JSON_FLAG);
        String key = inputLine.getNextArgFor(UPDATE_KEY_FLAG);
        String value = inputLine.getNextArgFor(UPDATE_VALUE_FLAG);
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("no entry for \"" + identifiable.getIdentifierString() + "\" found.");
            return;
        }
        if (addFlag && removeFlag) {
            say("Error: You cannot add and remove a value the same time");
            return;
        }
        if (jsonFlag) {
            JSONObject json = getJSONArg(inputLine);
            if (addFlag) {
                addEntry(identifiable, json);
            }
            if (removeFlag) {
                removeEntry(identifiable, json);
            }
              return;
        }

        if (addFlag) {
            addEntry(identifiable, inputLine.getNextArgFor(UPDATE_KEY_FLAG), inputLine.getNextArgFor(UPDATE_VALUE_FLAG));
        }
        if(removeFlag){
            removeEntry(identifiable, inputLine.getNextArgFor(UPDATE_KEY_FLAG), inputLine.getNextArgFor(UPDATE_VALUE_FLAG));

        }

    }


    protected void addEntry(Identifiable identifiable, String key, String value) {
        JSONObject json = new JSONObject();
        json.put(key, value);
        addEntry(identifiable, json);
    }

    /**
     * Proposed changes to store to allow for adding updates and removing them via batch files.
     * At this point this is considered experimental.
     * @param identifiable
     * @param json
     */
   protected abstract void addEntry(Identifiable identifiable, JSONObject json);

    protected abstract void removeEntry(Identifiable identifiable, JSONObject json);

    protected void removeEntry(Identifiable identifiable, String key, String value) {
        JSONObject json = new JSONObject();
        json.put(key, value);
        removeEntry(identifiable, json);
    }


    public void list_keys(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showListKeysHelp();
            return;
        }
        XMLConverter xmlConverter = getStore().getXMLConverter();
        if (xmlConverter instanceof MapConverter) {
            MapConverter mc = (MapConverter) xmlConverter;
            for (String key : mc.getKeys().allKeys()) {
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
     protected JSONObject getJSONArg(InputLine inputLine){
         String[] args2 = inputLine.argsToStringArray();
         String raw2 = "";
         for(int i = 0; i < args2.length -1 ; i++){
              raw2 = raw2+args2[i];
         }
         int start = raw2.indexOf("'");
         int end = raw2.lastIndexOf("'");
         String rawJSON = raw2.substring(start+1, end);
         try{
              return JSONObject.fromObject(rawJSON);
         }catch(Throwable t){
             return new JSONObject();
         }
     }
    public static void main(String[] args){
        CommandLineTokenizer CLT = new CommandLineTokenizer();
        String raw = "update -add -json '{\"fnord\":[\"blarf0\",\"blarf1\"]}' /foo:bar";

        Vector v = CLT.tokenize(raw);
        System.out.println(v);
        InputLine inputLine = new InputLine(v);
    }


}
