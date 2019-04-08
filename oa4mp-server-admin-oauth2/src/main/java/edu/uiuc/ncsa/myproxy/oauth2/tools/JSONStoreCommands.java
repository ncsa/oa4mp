package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.LineEditor;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.*;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/21/19 at  7:33 PM
 */
public class JSONStoreCommands extends StoreCommands2 {
    public JSONStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public JSONStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "json";
    }

    protected boolean updateProcedure(JSONEntry jsonEntry) {
        String response = getInput("Did you want to import the JSON from a file? (y/n)", "n");
        String rawContent = "";
        if (response.equals("y")) {
            say("Enter path and file name:");
            String f = readline();

            // now to create some object.
            rawContent = readFile(f);
            if (rawContent == null) {
                return false; //this means the read was aborted for some reason
            }

        } else {
             rawContent = getFromEditor("");
        }
        jsonEntry.setType(JSONEntry.TYPE_PROCEDURE);
        jsonEntry.setRawContent(rawContent);
        return true;
    }

    protected String getFromEditor(String raw) {
        LineEditor lineEditor = new LineEditor(raw);
        try {
            lineEditor.execute();
        } catch (Throwable throwable) {
            throwable.printStackTrace();
        }
        String rc = getInput("save (y/n)?", "y");
        if (rc.equals("y")) {
            return lineEditor.bufferToString();
        } else {
            return null;
        }

    }

    protected String readFile(String path) {
        try {
            File file = new File(path);
            if (!file.exists()) {
                say("Sorry, no such file");
                return null;
            }
            FileReader fileReader = new FileReader(file);
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            StringBuffer lines = new StringBuffer();
            String inLine = bufferedReader.readLine();
            while (inLine != null) {
                lines.append(inLine + "\n");
                inLine = bufferedReader.readLine();
            }
            bufferedReader.close();
            return lines.toString();
        } catch (FileNotFoundException e) {
            if(isDebugOn()) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            if(isDebugOn()) {
                e.printStackTrace();
            }
        }

        return null;
    }

    protected boolean updateJSON(JSONEntry jsonEntry) {
        String response = getInput("Did you want to import the JSON from a file? (y/n)", "n");
        String rawContent = "";
        JSON newJSON = null;
        if (response.equals("y")) {
            say("Enter path and file name:");
            String f = readline();

            // now to create some object.
            rawContent = readFile(f);
            if (rawContent == null) {
                return false; //this means the read was aborted for some reason
            }
        } else {
            rawContent = getFromEditor("{}");
        }
        newJSON = createJSONFromLines(rawContent);
        if (newJSON == null) return false;
        if (newJSON instanceof JSONObject) {
            jsonEntry.setType(JSONEntry.TYPE_JSON_OBJECT);
        }
        if (newJSON instanceof JSONArray) {
            jsonEntry.setType(JSONEntry.TYPE_JSON_ARRAY);
        }
        jsonEntry.setRawContent(rawContent);

        return true;
    }

    @Override
    public boolean update(Identifiable identifiable) {
        info("Starting JSON update for id = " + identifiable.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        JSONEntry jsonEntry = (JSONEntry) identifiable;
        String newIdentifier = getInput("enter the identifier", jsonEntry.getIdentifierString());


        boolean removeCurrentObject = false;
        if (!newIdentifier.equals(jsonEntry.getIdentifierString())) {
            sayi2(" remove json object with id=\"" + jsonEntry.getIdentifier() + "\" [y/n]? ");
            removeCurrentObject = isOk(readline());
            jsonEntry.setIdentifier(BasicIdentifier.newID(newIdentifier));
        }

        String response = getInput("Did you want to enter a procedure or JSON (p/j)?", "j");
        if (response.equals("p")) {
            jsonEntry.setType(JSONEntry.TYPE_PROCEDURE);
            return updateProcedure(jsonEntry);
        }
        if (response.equals("j")) {
            return updateJSON(jsonEntry);
        }
        return false; // default is to bail and do nothing.
    }


    @Override
    public void extraUpdates(Identifiable identifiable) {
//        JSONEntry jsonEntry = (JSONEntry) identifiable;
    }


    @Override
    protected String format(Identifiable identifiable) {
        JSONEntry je = (JSONEntry) identifiable;

        return je.getIdentifier() + " created at " + je.getCreationTimestamp() + ". ";
    }

    @Override
    protected void longFormat(Identifiable identifiable) {
        JSONEntry je = (JSONEntry) identifiable;
        say("id=" + je.getIdentifier());
        say("created at " + je.getCreationTimestamp());
        say("last modifed at " + je.getLastModified());
        if (je.getRawContent() == null || je.getRawContent().isEmpty()) {
            say("(empty)");
            return;
        }
        if (je.isJSONObject()) {
            say(je.getObject().toString(1));
        }
        if (je.isArray()) {
            say(je.getArray().toString(1));
        }
        if (je.isProcedure()) {
            List<String> proc = je.getProcedure();
            for (String p : proc)
                say(p);
        }
    }

    /**
     * Takes the lines of a file and turns it in to a JSON object.
     *
     * @param raw
     * @return
     */
    protected JSON createJSONFromLines(String raw) {
        JSON newJSON = null;
        try {
            newJSON = JSONObject.fromObject(raw);
        } catch (Throwable t) {
            try {
                newJSON = JSONArray.fromObject(raw);
            } catch (Throwable t2) {
                say("Sorry but that did not parse as JSON. Message is \"" + t2.getMessage() + "\"");
            }
        }
        return newJSON;
    }

    /**
     * Take a file with a procedure in it and turn it in to an array of lines. This is how the procedure is stored
     * in the {@link edu.uiuc.ncsa.security.util.json.JSONStore}.
     *
     * @param lines
     * @return
     */
    protected JSONArray createProcedureFromLines(List<String> lines) {
        JSONArray array = new JSONArray();
        array.addAll(lines);
        return array;
    }
}
