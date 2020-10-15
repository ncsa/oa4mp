package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.qdl.util.QDLVersion;
import edu.uiuc.ncsa.security.core.configuration.XProperties;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.cli.LineEditor;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

import java.io.StringReader;
import java.util.Arrays;
import java.util.Date;

import static edu.uiuc.ncsa.qdl.scripting.Scripts.*;

/**
 * This set of commands lets you put in qdl script and manage them in the command line client.
 * @deprecated -- format of scripts changed and this was not updated.
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/20 at  12:38 PM
 */
public class QDLCLICommands extends CommonCommands {
    @Override
    public String getPrompt() {
        return "qdl>";
    }

    public QDLCLICommands(MyLoggingFacade logger) {
        super(logger);
    }

    public QDLCLICommands(MyLoggingFacade logger, ScriptSet scriptSet) {
        super(logger);
        this.scriptSet = scriptSet;
    }

    public ScriptSet<QDLScript> getScriptSet() {
        return scriptSet;
    }

    public void setScriptSet(ScriptSet<QDLScript> scriptSet) {
        this.scriptSet = scriptSet;
    }

    ScriptSet<QDLScript> scriptSet;


    public void list_phases(InputLine inputLine) throws Exception {
        say("Supported phases:" + Arrays.toString(ScriptingConstants.SRE_PHASES));
        say("current phases:");
        for (QDLScript q : scriptSet.getScripts()) {
            System.out.println("  " + q.getProperties().getString(EXEC_PHASE));
        }
    }

    protected String shortFormat(QDLScript script) {
        String output = EXEC_PHASE + "=" + script.getProperties().getString(EXEC_PHASE);
        output = output + ",  " + ID + "=" + script.getProperties().getString(ID);

        return output;
    }

    protected String format(QDLScript script) {
        String output = "";
        for (Object key : script.getProperties().keySet()) {
            output = output + key + ": " + script.getProperties().getString(key.toString()) + "\n";
        }
        output = output + "\n";
        output = output + script.getText() + (script.getText().endsWith("\n") ? "" : "\n") + "------\n";
        return output;
    }

    protected void showLSHelp() {
        say("ls [-la] [-" + ID + "|-" + EXEC_PHASE + " arg]");
        sayi("This will print out a given script keying on its id or its phase or if");
        sayi("none is given, it will print out a summary of all the scripts.");
        sayi("-la = long format, so all of the properties as well as the script body are printed.");
    }

    public void ls(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showLSHelp();
            return;
        }
        QDLScript s = null;
        boolean hasID = false;
        boolean longFormat = inputLine.hasArg("-la");

        if (inputLine.hasArg(EXEC_PHASE)) {
            s = (QDLScript) scriptSet.get(EXEC_PHASE, inputLine.getNextArgFor(EXEC_PHASE));
            hasID = true;
        }
        if (inputLine.hasArg(ID)) {
            s = (QDLScript) scriptSet.get(ID, inputLine.getNextArgFor(ID));
            hasID = true;
        }
        if (hasID) {
            if (s == null) {
                say("sorry, could not find a script for that.");
                return;
            } else {
                if (longFormat) {
                    say(format(s));
                } else {
                    shortFormat(s);
                }
                return;
            }
        }
        say("Current scripts:");
        for (QDLScript s2 : scriptSet.getScripts()) {
            if (inputLine.hasArg("-la")) {
                say(format(s2));
            } else {
                say(shortFormat(s2));
            }
        }
    }

    protected void editHelp() {
        say("update -phase | -id arg -- update a script given the phase or the identifier");
    }

    public void update(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            editHelp();
            return;
        }
        QDLScript script = (QDLScript) scriptSet.get(EXEC_PHASE, inputLine.getNextArgFor("-phase"));

        LineEditor lineEditor = new LineEditor(script.getText());
        try {
            lineEditor.execute();
            if (!lineEditor.isSaved()) {
                String inLine = getInput("Did you want to save the buffer? (y/n):", "y");
                if (inLine.equals("y")) {
                    //    return QDLJSONConfigUtil.createCfgFromString(lineEditor.bufferToString(), execPhase);
                    script.setLines(lineEditor.getBuffer());
                    script.getProperties().setString(LAST_MODIFIED, Iso8601.date2String(new Date()));
                }
            }
        } catch (Throwable t) {
            say("well, that didn't work:" + t.getMessage());
        }
    }

    protected void showCreateHelp() {
        say("create ");
        sayi("Create a new script.");
    }

    public void create(InputLine inputLine) throws Exception {
        String phase = getInput("Enter phase:", "");
        boolean replaceIt = false;
        if (scriptSet.get(EXEC_PHASE, phase) != null) {
            if (!getInput(
                    "there is a script for the phase \"" + phase + "\". Did you want to replace it?[y/n]",
                    "y").equalsIgnoreCase("y")) {
                say("aborting...");
                return;
            } else {
                replaceIt = true; // they can opt to replace it here.
            }
        }

        String id = getInput("Enter id:[" + phase + QDLVersion.DEFAULT_FILE_EXTENSION + "]", phase + QDLVersion.DEFAULT_FILE_EXTENSION);
        if (!replaceIt && scriptSet.get(ID, id) != null) {
            if (getInput(
                    "there is a script for the id \"" +
                            id + "\". Did you want to replace it?[y/n]",
                    "y").equalsIgnoreCase("y")) {
                say("aborting...");
                return;
            }
        }

        LineEditor lineEditor = new LineEditor("");
        QDLScript script = null;
        try {
            lineEditor.execute();
            if (!lineEditor.isSaved()) {
                String inLine = getInput("Did you want to save the buffer? (y/n):", "y");
                if (inLine.equals("y")) {
                    //    return QDLJSONConfigUtil.createCfgFromString(lineEditor.bufferToString(), execPhase);
                    XProperties xp = new XProperties();
                    xp.put(EXEC_PHASE, phase);
                    xp.put(ID, id);
                    xp.put(CREATE_TIME, Iso8601.date2String(new Date()));
                    xp.put(LAST_MODIFIED, Iso8601.date2String(new Date()));
                    xp.put(LANGUAGE, QDLVersion.LANGUAGE_NAME);
                    xp.put(LANG_VERSION, QDLVersion.VERSION);
                    xp.put(SCRIPT_VERSION, "1.0");
                    script = new QDLScript(new StringReader(lineEditor.bufferToString()), xp);
                    scriptSet.add(script);
                }
            }

        } catch (Throwable t) {
            say("sorry, but there was an error running the editor:" + t.getMessage());
            return;
        }

    }
}