package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.ScriptingConstants;
import edu.uiuc.ncsa.qdl.scripting.JSONScriptUtil;
import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.qdl.util.FileUtil;
import edu.uiuc.ncsa.qdl.util.QDLVersion;
import edu.uiuc.ncsa.security.core.configuration.XProperties;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import net.sf.json.JSONObject;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.io.File;
import java.io.StringReader;
import java.util.Date;

import static edu.uiuc.ncsa.qdl.scripting.Scripts.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  3:21 PM
 */
public class QDLJSONConfigUtil implements ScriptingConstants {
    /**
     * Creates a script from a file. Note that this takes a convenience approach:
     * If the file name is the same as one of the execute phases, the phase is
     * set to that and you are done. If not, you must set it later if needed.
     * @param fileName
     * @return
     * @throws Throwable
     */
    public static JSONObject createCfg(String fileName) throws Throwable {
        // For new call.
        return createCfg(new JSONObject(), fileName);
    }



    /**
     * NOTE that this creates the JSONObject, but does not
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
        QDLScript qdlScript = new QDLScript(new StringReader(rawScript), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);
        jsonObject.put("config2", scripts);
        return jsonObject;

       }
    public static JSONObject createCfg(JSONObject jsonObject, String fileName) throws Throwable {
        String script = FileUtil.readFileAsString(fileName);
        XProperties xp = new XProperties();

        String scriptName = fileName.substring(fileName.lastIndexOf(".")); // drop extension
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
            default:
                // no automatic phase given. Have to get it
                xp.put(EXEC_PHASE, OA2ClaimsUtil.SRE_NO_EXEC_PHASE);
        }

        xp.put(ID, fileName);
        xp.put(LANGUAGE, QDLVersion.LANGUAGE_NAME);
        xp.put(LANG_VERSION, QDLVersion.VERSION);
        xp.put(SCRIPT_VERSION, "1.0");
        xp.put(CREATE_TIME, Iso8601.date2String(new Date()));
        QDLScript qdlScript = new QDLScript(new StringReader(script), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);
        jsonObject.put("config2", scripts);
        return jsonObject;

    }

    /**
     * This will take a given directory and read <b><i>EVERYTHING</i></b> in it and return
     * a JSON representation of it. The scripting facility will treat this as a library and
     * when evaluating it, will create a virtual file system (VFS) against which you may make calls.
     * <br/><br/>
     * In server mode, only such a VFS is available. Calls for other scripts, loading modules and reading
     * files will all be done against this, so you don't need to worry about it.
     * @param dir
     * @return
     * @throws Throwable
     */
    public static JSONObject readDir(File dir) throws Throwable {
        if(dir != null){
            throw new NotImplementedException(); // need to finish this, but don't have time right now.
        }
        if(!dir.exists()){
            throw new IllegalStateException("Error: \"" + dir + "\" does not exist.");
        }
        if(!dir.isDirectory()){
            throw new IllegalArgumentException("Error: \"" + dir + "\" must be a directory.");
        }
        if(!dir.canRead()){
            throw new IllegalStateException("Error: \"" + dir + "\" cannot be read.");
        }
       JSONObject jsonObject = new JSONObject();
        dir.listFiles();
        for(File file : dir.listFiles()){
            if(file.isDirectory()){
                readDir(file);
            }else{

            }
        }
         return jsonObject;
    }


    public static JSONObject readDir(String directory) throws Throwable {
                  return readDir(new File(directory));
    }

    public static JSONObject createNCSA() {
        // Creates a fully functional client to access the NCSA LDAP. Note that the uid claim has to be set
        // (because we can't get it from local login) and there has to be a connection the VPN for this
        // to work.
        JSONObject jsonObject = new JSONObject();

        StringBuffer script = new StringBuffer();
        script.append("claims.uid := 'jgaynor';\n");
        script.append("f. := new_template('ncsa');\n");
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
               xp.put(ID, SRE_PRE_AT+ QDLVersion.DEFAULT_FILE_EXTENSION);
               xp.put(LANGUAGE, "qdl");
               xp.put(LANG_VERSION, "1.0");
               xp.put(SCRIPT_VERSION, "1.0");
               qdlScript = new QDLScript(new StringReader(script.toString()), xp);
               JSONScriptUtil.addScript(scripts, qdlScript);




        jsonObject.put("config2", scripts);
        System.out.println(jsonObject.toString(2));
        return jsonObject;

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
        xp.put(ID, SRE_EXEC_INIT+ QDLVersion.DEFAULT_FILE_EXTENSION);
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
        xp.put(ID, SRE_PRE_AT+ QDLVersion.DEFAULT_FILE_EXTENSION);
        xp.put(LANGUAGE, "qdl");
        xp.put(LANG_VERSION, "1.0");
        xp.put(SCRIPT_VERSION, "1.0");
        qdlScript = new QDLScript(new StringReader(script.toString()), xp);
        scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);



        jsonObject.put("config2", scripts);
        System.out.println(jsonObject.toString(2));
        return jsonObject;
    }

    public static void main(String[] args) {
        createNCSA();
    }
}
