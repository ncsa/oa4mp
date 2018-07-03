package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.StoreCommands;

import java.io.*;

/**
 * This class exists because we cannot quite get the dependencies right otherwise. Mostly it is to have access
 * to converters for de/serialization.
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
    protected abstract MapConverter getConverter();

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
                is = new FileInputStream(inputLine.getArg(1 + inputLine.indexOf("-file")));
                XMLMap map = new XMLMap();
                map.fromXML(is);
                is.close();
                Identifiable x = getConverter().fromMap(map);
                if (isNew) {
                    if (getStore().containsKey(x.getIdentifier())) {
                        say("Error! The object with identifier \"" + x.getIdentifierString() + "\" already exists and you specified the item was new. Aborting.");
                        return;
                    }
                } else {
                    if(x.getIdentifier() == null){
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
                say("warning, could not find file at path " + inputLine.getArg(inputLine.indexOf("-file")));
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
        getConverter().toMap(x, c);
        OutputStream os = System.out;
        boolean hasFile = false;
        if (inputLine.hasArg("-file")) {
            try {
                os = new FileOutputStream(inputLine.getArg(1 + inputLine.indexOf("-file")));
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
}
