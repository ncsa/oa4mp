package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.Subject;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.SubjectAdmin;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.SubjectClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.*;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  10:24 AM
 */
public class ThingFactory implements SAT {
    public static Subject getSubject(JSONObject json) {

        switch (getSubjectValue(json)) {
            case SUBJECT_ADMIN_VALUE:
                return new SubjectAdmin();
            case SUBJECT_CLIENT_VALUE:
                return new SubjectClient();
            default:
                throw new IllegalArgumentException("Unknown subject \"" + getV(json, KEYS_SUBJECT) + "\"");
        }
    }

    public static Target getTarget(JSONObject json) {
        switch (getTargetValue(json)) {
            case TARGET_ADMIN_VALUE:
                return new TargetAdmin();
            case TARGET_CLIENT_VALUE:
                return new TargetClient();
            case TARGET_ATTRIBUTE_VALUE:
                return new TargetAttribute();
            case TARGET_PERMISSION_VALUE:
                return new TargetPermission();
            default:
                throw new IllegalArgumentException("Unknown target \"" + getV(json, KEYS_TARGET) + "\"");
        }
    }

    public static Action getAction(JSONObject json) {
        switch (getActionValue(json)){
            case ACTION_ADD_VALUE:
                return new ActionAdd();
            case ACTION_APPROVE_VALUE:
                return new ActionApprove();
            case ACTION_CREATE_VALUE:
                return new ActionCreate();
            case ACTION_EXECUTE_VALUE:
                return new ActionExecute();
            case ACTION_GET_VALUE:
                return new ActionGet();
            case ACTION_LIST_VALUE:
                return new ActionList();
            case ACTION_REMOVE_VALUE:
                return new ActionRemove();
            case ACTION_SET_VALUE:
                return new ActionSet();
            default:
                throw new IllegalArgumentException("Unknown action \"" + getV(json, KEYS_ACTION) + "\"");
        }
    }


    public static Identifier getIdentifier(JSONObject json){
        JSONObject id = json.getJSONObject(SAT.KEYS_ID);
        return BasicIdentifier.newID(id.getString("id"));

    }
    public static String getSecret(JSONObject json){
        JSONObject id = json.getJSONObject(SAT.KEYS_ID);
        return id.getString("secret");

    }
    public static JSONObject getArgument(JSONObject json){
        return json.getJSONObject(SAT.KEYS_CONTENT);
    }
    protected static String getV(JSONObject json, String key) {
        return json.getString(key).toLowerCase();
    }

    protected static int getSubjectValue(JSONObject json) {
        if (getV(json, KEYS_SUBJECT).equals(SUBJECT_CLIENT)) return SUBJECT_CLIENT_VALUE;
        if (getV(json, KEYS_SUBJECT).equals(SUBJECT_ADMIN)) return SUBJECT_ADMIN_VALUE;
        return NO_VALUE;

    }

    protected static int getTargetValue(JSONObject json) {
        if (getV(json, KEYS_TARGET).equals(TARGET_ADMIN)) return TARGET_ADMIN_VALUE;
        if (getV(json, KEYS_TARGET).equals(TARGET_CLIENT)) return TARGET_CLIENT_VALUE;
        if (getV(json, KEYS_TARGET).equals(TARGET_ATTRIBUTE)) return TARGET_ATTRIBUTE_VALUE;
        if (getV(json, KEYS_TARGET).equals(TARGET_PERMISSION)) return TARGET_PERMISSION_VALUE;
        return NO_VALUE;

    }

    protected static int getActionValue(JSONObject json) {
        if (getV(json, KEYS_ACTION).equals(ACTION_ADD)) return ACTION_ADD_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_APPROVE)) return ACTION_APPROVE_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_CREATE)) return ACTION_CREATE_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_EXECUTE)) return ACTION_EXECUTE_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_GET)) return ACTION_GET_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_LIST)) return ACTION_LIST_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_REMOVE)) return ACTION_REMOVE_VALUE;
        if (getV(json, KEYS_ACTION).equals(ACTION_SET)) return ACTION_SET_VALUE;

        return NO_VALUE;
    }
}
