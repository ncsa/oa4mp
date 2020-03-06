package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.qdl.vfs.FileEntries;
import edu.uiuc.ncsa.qdl.scripting.JSONScriptUtil;
import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.qdl.util.FileUtil;
import edu.uiuc.ncsa.qdl.util.QDLVersion;
import edu.uiuc.ncsa.security.core.configuration.XProperties;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.oauth_2_0.jwt.ScriptingConstants;
import edu.uiuc.ncsa.security.util.scripting.ScriptSet;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.File;
import java.io.StringReader;
import java.util.Date;

import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine.CONFIG_TAG;
import static edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.QDLRuntimeEngine.SCRIPTS_TAG;
import static edu.uiuc.ncsa.qdl.scripting.Scripts.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  3:21 PM
 */
public class QDLJSONConfigUtil implements ScriptingConstants {
    /**
     * Takes a list
     *  of @link QDLScript} objects and turns it in to a QDL configuration,
     *  i.e. this gets  <br/><br/>
     * {script, script,...}<br/><br/>
     * and returns a new JSON object consisting of<br/>
     * <pre>
     * {"qdl":{"scripts":[...]}}
     * </pre>
     * turning the list of scripts in to the JSON array.
     *
     * @param scriptSet
     * @return
     */
    public static JSONObject scriptSetToJSON(ScriptSet<? extends QDLScript> scriptSet) {
        JSONObject scripts = JSONScriptUtil.createConfig();
        for (QDLScript s : scriptSet.getScripts()) {
            JSONScriptUtil.addScript(scripts, s);
        }
        JSONObject config = new JSONObject();
        config.put(CONFIG_TAG, scripts);
        return config;
    }

    /**
     * This assumes that the configuration is the scripts tag, not the entire configuration.
     * I.e. the thing passed in is the entry here:
     * <pre>
     *     {"qdl":{"scripts":[...]}}
     * </pre>
     * This returns the [...] array of script objects as a list of {@link QDLScript} objects
     *
     * @param config
     * @return
     */
    public static ScriptSet readScriptSet(JSONObject config) {
        JSONArray array = config.getJSONArray(SCRIPTS_TAG);
        // QDLScriptLibrary library = new QDLScriptLibrary(QDL_VIRTUAL_FILE_SYSTEM_SCHEME);
        ScriptSet<QDLScript> scriptSet = new ScriptSet<>();
        for (int i = 0; i < array.size(); i++) {
            QDLScript qdlScript = Scripts.fromJSON(array.getJSONObject(i));
            scriptSet.add(qdlScript);
        }
        return scriptSet;
    }

    /**
     * Creates a script from a file. Note that this takes a convenience approach:
     * If the file name is the same as one of the execute phases, the phase is
     * set to that and you are done. If not, you must set it later if needed.
     * See also {@link #createCfg(JSONObject, String)} which does the actual work.
     * @param fileName
     * @return
     * @throws Throwable
     */
    public static JSONObject createCfg(String fileName) throws Throwable {
        // For new call.
        return createCfg(new JSONObject(), fileName);
    }


    /**
     * NOTE that this creates the JSONObject from a string, but does not have a file, so it creates a file name
     * that is the execution phase. This takes a line which is the actual script and a phase then
     * creates a {@link QDLScript} from it, which is turned in to a complete JSON configuration.
     * <br/><br/>

     *
     * @param rawScript
     * @return
     * @throws Throwable
     */
    public static JSONObject createCfgFromString(String rawScript, String execPhase) throws Throwable {
        JSONObject jsonObject = new JSONObject();
        XProperties xp = new XProperties();
        xp.put(ID, execPhase + QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(EXEC_PHASE, execPhase);
        xp.put(LANGUAGE, QDLVersion.LANGUAGE_NAME);
        xp.put(LANG_VERSION, QDLVersion.VERSION);
        xp.put(SCRIPT_VERSION, "1.0");
        xp.put(CREATE_TIME, Iso8601.date2String(new Date()));
        xp.put(LAST_MODIFIED, Iso8601.date2String(new Date()));
        QDLScript qdlScript = new QDLScript(new StringReader(rawScript), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);
        jsonObject.put(CONFIG_TAG, scripts);
        return jsonObject;

    }

    /**
     * This creates a simple script with no path information, just the name for the file and
     * will add it to the {@link JSONObject} argument
     * <br/><br/>
     * So this read a file, creates a {@link QDLScript} from its contents and adds it to the
     * current list of scripts. 
     * @param currentConfig
     * @param filePath
     * @return
     * @throws Throwable
     */
    public static JSONObject createCfg(JSONObject currentConfig, String filePath) throws Throwable {
        String fileName = filePath.substring(filePath.lastIndexOf(File.pathSeparator));
        QDLScript qdlScript = createCfg(fileName, filePath);
        JSONObject scripts = null;
        if(currentConfig.containsKey(CONFIG_TAG)){
            scripts = currentConfig.getJSONObject(CONFIG_TAG); // so we add to it
        }else {
            scripts = JSONScriptUtil.createConfig();
        }
        JSONScriptUtil.addScript(scripts, qdlScript);
        currentConfig.put(CONFIG_TAG, scripts);
        return currentConfig;

    }

    /**
     * This will create a QDL script with the relative path.
     *
     * @param relativePath -- the path relative some directory including file name
     * @param absolutePath -- the actual path on the system that will be used to load this script.
     * @return
     * @throws Throwable
     */
    protected static QDLScript createCfg(String relativePath, String absolutePath) throws Throwable {

        String script = FileUtil.readFileAsString(absolutePath);
        XProperties xp = new XProperties();
        String scriptName = absolutePath.substring(absolutePath.lastIndexOf(File.separator) + 1); // drop extension
        scriptName = scriptName.substring(0, scriptName.lastIndexOf("."));
        switch (scriptName) {
            case SRE_EXEC_INIT:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_EXEC_INIT);
                break;
            case SRE_PRE_AUTH:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_PRE_AUTH);
                break;
            case SRE_POST_AUTH:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_POST_AUTH);
                break;
            case SRE_PRE_AT:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_PRE_AT);
                break;
            case SRE_POST_AT:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_POST_AT);
                break;
            case SRE_PRE_REFRESH:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_PRE_REFRESH);
                break;
            case SRE_POST_REFRESH:
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_POST_REFRESH);
                break;
            default:
                // no automatic phase given. Have to get it
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_NO_EXEC_PHASE);
        }
       File f = new File(absolutePath);
        Date createTS = new Date();
                  createTS.setTime(f.lastModified());
        xp.put(ID, relativePath);
        xp.put(LANGUAGE, QDLVersion.LANGUAGE_NAME);
        xp.put(LANG_VERSION, QDLVersion.VERSION);
        xp.put(SCRIPT_VERSION, "1.0");
        xp.put(CREATE_TIME, Iso8601.date2String(createTS));
        xp.put(LAST_MODIFIED, Iso8601.date2String(createTS));
        xp.put("length", f.length());
        QDLScript qdlScript = new QDLScript(new StringReader(script), xp);
        return qdlScript;
    }

    /**
     * <h1>NOTE This is under development and should not be used yet!</h1>
     * This will take a given directory and read <b><i>EVERYTHING</i></b> in it and return
     * a JSON representation of it. The scripting facility will treat this as a library and
     * when evaluating it, will create a virtual file system (VFS) against which you may make calls.
     * <br/><br/>
     * In server mode, only such a VFS is available. Calls for other scripts, loading modules and reading
     * files will all be done against this, so you don't need to worry about it.
     *
     * @param rootDir
     * @return
     * @throws Throwable
     */
    public static JSONObject readDir(File rootDir) throws Throwable {

        if (!rootDir.exists()) {
            throw new IllegalStateException("Error: \"" + rootDir + "\" does not exist.");
        }
        if (!rootDir.isDirectory()) {
            throw new IllegalArgumentException("Error: \"" + rootDir + "\" must be a directory.");
        }
        if (!rootDir.canRead()) {
            throw new IllegalStateException("Error: \"" + rootDir + "\" cannot be read.");
        }
        JSONObject repo = new JSONObject();
        for (File file : rootDir.listFiles()) {
            if (file.isDirectory()) {
                readDir(rootDir, file, repo);
            } else {
                String relative = rootDir.toURI().relativize(file.toURI()).getPath();

                if (relative.endsWith(QDLVersion.DEFAULT_FILE_EXTENSION)) {
                    QDLScript qdlScript = createCfg(relative, file.getAbsolutePath());
                    JSONScriptUtil.addScript(repo, qdlScript);
                } else {
                    FileEntries.addFile(repo, relative, file);
                }
            }
        }
        return repo;
    }


    public static JSONObject readDir(File rootDir, File dir, JSONObject repo) throws Throwable {
        for (File file : dir.listFiles()) {
            if (file.isDirectory()) {
                readDir(rootDir, file, repo);
            } else {
                String relative = rootDir.toURI().relativize(file.toURI()).getPath();

                if (relative.endsWith(QDLVersion.DEFAULT_FILE_EXTENSION)) {
                    QDLScript qdlScript = createCfg(relative, file.getAbsolutePath());
                    JSONScriptUtil.addScript(repo, qdlScript);
                } else {
                    FileEntries.addFile(repo, relative, file);
                }
            }
        }
        return repo;
    }

    public static JSONObject readDir(String directory) throws Throwable {
        return readDir(new File(directory));
    }

    public static JSONObject createNCSA() {
        // Creates a fully functional client to access the NCSA LDAP. Note that the uid claim has to be set
        // (because we can't get it from local login) and there has to be a connection the VPN for this
        // to work.

        StringBuffer script = new StringBuffer();
        script.append("claims.uid := 'jgaynor';\n");
        script.append("f. := new_template('ncsa');\n");
        script.append("claim_sources.0. := create_source(f.);\n");
        XProperties xp = new XProperties();
        xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_PRE_AUTH);
        xp.put(ID, SRE_PRE_AUTH + QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(LANGUAGE, "qdl");
        xp.put(LANG_VERSION, "1.0");
        xp.put(SCRIPT_VERSION, "1.0");
        QDLScript qdlScript = new QDLScript(new StringReader(script.toString()), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
       scripts =  JSONScriptUtil.addScript(scripts, qdlScript);

        script = new StringBuffer();
        script.append("if[");
        script.append("  in_group(claims.isMemberOf., 'all_users')");
        script.append("]then[");
        script.append("  claims.check := 'in group';");
        script.append("]else[");
        script.append("  claims.check := 'not in group';");
        script.append("]; //end if");
        xp = new XProperties();
        xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_POST_AT);
        xp.put(ID, SRE_POST_AT + QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(LANGUAGE, "qdl");
        xp.put(LANG_VERSION, "1.0");
        xp.put(SCRIPT_VERSION, "1.0");
        qdlScript = new QDLScript(new StringReader(script.toString()), xp);
       scripts =  JSONScriptUtil.addScript(scripts, qdlScript);

        JSONObject jsonObject = new JSONObject();

        jsonObject.put(CONFIG_TAG, scripts);
        System.out.println(jsonObject.toString(2));
        return jsonObject;

    }

    protected JSONObject createFileEntry(String contents) {
        return new JSONObject();

    }

    public static JSONObject createFS() {
        // Creates a fully functional configuration for a client to access the local FS claim source
        JSONObject jsonObject = new JSONObject();

        StringBuffer script = new StringBuffer();
        script.append("f. := new_template('file');\n");
        script.append("f.file_path := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources/test-claims.json';\n");
        script.append("claim_sources.0. := create_source(f.);\n");
        XProperties xp = new XProperties();
        xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_EXEC_INIT);
        xp.put(ID, SRE_EXEC_INIT + QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(LANGUAGE, "qdl");
        xp.put(LANG_VERSION, "1.0");
        xp.put(SCRIPT_VERSION, "1.0");
        QDLScript qdlScript = new QDLScript(new StringReader(script.toString()), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);

        script = new StringBuffer();
        script.append("say(claim_sources.);");
        script.append("say(flow_states.);");
        xp = new XProperties();
        xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_PRE_AT);
        xp.put(ID, SRE_PRE_AT + QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(LANGUAGE, "qdl");
        xp.put(LANG_VERSION, "1.0");
        xp.put(SCRIPT_VERSION, "1.0");
        qdlScript = new QDLScript(new StringReader(script.toString()), xp);
        scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);


        jsonObject.put(CONFIG_TAG, scripts);
        System.out.println(jsonObject.toString(2));
        return jsonObject;
    }

    protected static void testLoadDir() {
        try {
            String directory = "/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-qdl/src/main/resources/scripts";
            JSONObject j = readDir(directory);
            JSONObject jsonObject = new JSONObject();

            jsonObject.put(CONFIG_TAG, j);
            System.out.println(jsonObject.toString(2));
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    public static void main(String[] args) {
        // testLoadDir();
       System.out.println(createNCSA().toString(1));
    }
}
