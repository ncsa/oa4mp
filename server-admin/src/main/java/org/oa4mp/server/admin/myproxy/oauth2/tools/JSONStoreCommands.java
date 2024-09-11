package org.oa4mp.server.admin.myproxy.oauth2.tools;

import org.oa4mp.server.admin.myproxy.oauth2.base.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.editing.LineEditor;
import edu.uiuc.ncsa.security.util.json.Ingester;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

/**
 * A utility to manage a store of JSON snippets.
 * @deprecated 
 * <p>Created by Jeff Gaynor<br>
 * on 2/21/19 at  7:33 PM
 */
public class JSONStoreCommands extends StoreCommands2 {
    protected JSONStore<JSONEntry> getJStore() {
        return (JSONStore<JSONEntry>) getStore();
    }

    public JSONStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable {
        super(logger, defaultIndent, store);
    }

    Ingester ingester = null;

    public Ingester getIngester() {
        if (ingester == null) {
            ingester = new Ingester((getJStore()));
        }
        return ingester;
    }

    @Override
    public String getName() {
        return "json";
    }

    protected boolean updateProcedure(JSONEntry jsonEntry) throws IOException {
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

    protected String getFromEditor(String raw) throws IOException {
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
            if (isDebugOn()) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            if (isDebugOn()) {
                e.printStackTrace();
            }
        }

        return null;
    }

    protected boolean updateJSON(JSONEntry jsonEntry) throws IOException {
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
        getStore().save(jsonEntry);
        return true;
    }
    protected void ingesterHelp(){
            say("ingest -file path -safe");
            say("      This will ingest a file. To ingest means that the file, which may contain");
            say("      either a single JSON object or an array of them, will be checked for a");
            say("      " + Ingester.STORE_ID_TAG + " tag. If present the value associated with this");
            say("      tag will be used as the id of the object. Note that the tag must be at the top level");
            say("      of the object. The tag will not be retained in the stored object's JSON.");
            say("      The default is to overwrite any existing entries in the store. You may specify ");
            say("      the -safe flag which will not overwrite existing entries.");
            say("      Note that if the file is a directory, then every file with a suffix of .json will be ingested");
            say("      You will be prompted though before ingesting a directory.");
    }
    /**
     * Ingest a file directly. The identifier can be included in the JSON and it will be used.
     * @param inputLine
     */

    public void ingest(InputLine inputLine) throws IOException {
        String fileName = inputLine.getNextArgFor("-file");
        boolean safeModeOff = !inputLine.hasArg("-safe");
        say("safe mode off = " + safeModeOff);
        if(showHelp(inputLine)){
            ingesterHelp();
            return;
        }
        if(fileName == null){
            say("Sorry, no file");
            return;
        }
        File file = new File(fileName);
        List<File> files = new ArrayList<>();
        if(file.isDirectory()){
            String resp = getInput("Process whole directory? Files ending in .json will be ingested", "y");
            if(resp.equals("y") ){
                FileFilter fileFilter = new FileFilter() {
                    @Override
                    public boolean accept(File pathname) {
                        if(!pathname.isDirectory()) {
                            return pathname.getName().endsWith(".json");
                        }
                        return false;
                    }
                };
                File[] fileList = file.listFiles(fileFilter);
                for(File f : fileList){
                    files.add(f);
                }
            }
        }else{
            files.add(file);
        }

        int totalCount = 0;
        List<Identifier> ids = new ArrayList<>();
        for(File f : files){
            totalCount++;
            try {
                 ids.addAll(getIngester().ingest(f, safeModeOff));
            } catch (IOException e) {
                say("failed to import " + f.getName() + ", message:\"" + e.getMessage() + "\"");
                e.printStackTrace();
            }

        }
        say("ingested " + ids.size() + " objects from " + totalCount + " files.");
    }
    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        info("Starting JSON update for id = " + identifiable.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        JSONEntry jsonEntry = (JSONEntry) identifiable;
        String newIdentifier = getInput("enter the identifier", jsonEntry.getIdentifierString());


        boolean removeCurrentObject = false;
        if (!newIdentifier.equals(jsonEntry.getIdentifierString())) {
            removeCurrentObject = isOk(readline(" remove json object with id=\"" + jsonEntry.getIdentifier() + "\" [y/n]? "));
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
    protected String format(Identifiable identifiable) {
        JSONEntry je = (JSONEntry) identifiable;

        return je.getIdentifier() + " created at " + je.getCreationTimestamp() + ". ";
    }

 /*   @Override
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
    }*/

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
