package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.StoreCommands;

import java.io.*;
import java.util.List;

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
                say("warning, could not find file at path \"" + inputLine.getNextArgFor("-file") + "\", " + e.getMessage());
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
                say("warning, could not find file at path " + inputLine.getArg(inputLine.indexOf("-file")));
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
        say("Searches the current component for all entries satisfying the condition. You may also specify that the ");
        say("condition is a regular expression rather than using simple equality");
        say("search -key key [-regex|-la -size] [-listKeys] condition");
        say("Invoking this with the -listkeys flag prints out all the keys for this store. Omit that for searches.");
        say("-key = the name of the key to be searched for");
        say("-regex (optional) attempt to interpret the conditional as a regular expression");
        say("-la (optional) print the result in long format.");
        say("-size (optional) print *only* the number of results.");
        say("\nE.g.\n");
        say("search -key client_id -regex \".*07028.*\"");
        say("\n(In the clients components) This would find the clients whose identifiers contain the string 07028");
        say("\nE.g.\n");
        say("search -key email -regex \".*bigstate\\.edu.*\"");
        say("\n(in the clients or user component) This would match all email addresses from that institution bigstate.edu. \n");
        say("Note that the period must be escaped for a regex.");

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
            List<Identifiable> values =null;
            try {
                values = getStore().search(key, inputLine.getLastArg(), inputLine.hasArg(REGEX_FLAG));
            }catch(Throwable t){
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
            say("\ngot " + values.size() + " match" + (values.size()==1?".":"es."));
        } else {
            say("Sorry, you must specify a key for the search. Try typing \nsearch " + LIST_KEYS_FLAG + "\n for all available keys");
        }

    }
}
