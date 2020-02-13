package edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.OA2ClaimsUtil;
import edu.uiuc.ncsa.qdl.scripting.JSONScriptUtil;
import edu.uiuc.ncsa.qdl.scripting.QDLScript;
import edu.uiuc.ncsa.qdl.scripting.Scripts;
import edu.uiuc.ncsa.security.core.configuration.XProperties;
import net.sf.json.JSONObject;

import java.io.StringReader;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/12/20 at  3:21 PM
 */
public class QDLJSONConfigUtil {
    public static JSONObject createCfg() {
        JSONObject jsonObject = new JSONObject();

        StringBuffer script = new StringBuffer();
        script.append("import('oa2:/qdl/oidc/claims');\n");
        script.append("f. := new_template('file');\n");
        script.append("f.file_path := '/home/ncsa/dev/ncsa-git/oa4mp/oa4mp-server-test-oauth2/src/main/resources/test-claims.json';\n");
        script.append("f2. := create_source(f.);\n");
        script.append("claim_sources.0. := f2.;\n");
        XProperties xp = new XProperties();
        xp.put(Scripts.EXEC_PHASE, OA2ClaimsUtil.SRE_EXEC_INIT);
        xp.put(Scripts.ID, "fs-init.qdl");
        xp.put(Scripts.LANGUAGE, "qdl");
        xp.put(Scripts.LANG_VERSION, "1.0");
        xp.put(Scripts.SCRIPT_VERSION, "1.0");
        QDLScript qdlScript = new QDLScript(new StringReader(script.toString()), xp);
        JSONObject scripts = JSONScriptUtil.createConfig();
        JSONScriptUtil.addScript(scripts, qdlScript);
        jsonObject.put("config2", scripts);
        System.out.println(jsonObject.toString(2));
        return jsonObject;

    }

    public static void main(String[] args) {
        createCfg();
    }
}
