package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.*;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  10:24 AM
 */
public class SATFactory implements SAT {
    static AdminClientConverter<? extends AdminClient> getACConverter() {
        return adminClientConverter;
    }

    public static void setAdminClientConverter(AdminClientConverter<? extends AdminClient> adminClientConverter) {
        SATFactory.adminClientConverter = adminClientConverter;
    }

    static AdminClientConverter<? extends AdminClient> adminClientConverter = null;

    public static ClientConverter<? extends Client> getClientConverter() {
        return clientConverter;
    }

    public static void setClientConverter(ClientConverter<? extends Client> clientConverter) {
        SATFactory.clientConverter = clientConverter;
    }

    static ClientConverter<? extends Client> clientConverter = null;


    public static int getSubjectValue(JSONObject json) {
            JSONObject api = json.getJSONObject(KEYS_API);
            JSONObject subject = api.getJSONObject(KEYS_SUBJECT);
            if (subject.containsKey(SUBJECT_ADMIN)) {
                return SUBJECT_ADMIN_VALUE;
            }

            if (subject.containsKey(SUBJECT_CLIENT)) {
                return SUBJECT_CLIENT_VALUE;
            }
            return SUBJECT_UNKNOWN_VALUE;
    }
    public static BaseClient getSubject(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject subject = api.getJSONObject(KEYS_SUBJECT);
        if (subject.containsKey(SUBJECT_ADMIN)) {
            return getACConverter().fromJSON(subject);
        }

        if (subject.containsKey(SUBJECT_CLIENT)) {
            return getClientConverter().fromJSON(subject);
        }
        return null;
    }

    public static int getTargetValue(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
              JSONObject target = api.getJSONObject(KEYS_TARGET);
              if (target.containsKey(SUBJECT_ADMIN)) {
                   return TARGET_ADMIN_VALUE;
               }

               if (target.containsKey(SUBJECT_CLIENT)) {
                   return TARGET_CLIENT_VALUE;
               }
        return TARGET_NO_VALUE;
    }
    public static BaseClient getTarget(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject target = api.getJSONObject(KEYS_TARGET);
        if (target.containsKey(SUBJECT_ADMIN)) {
             return getACConverter().fromJSON(target.getJSONObject(SUBJECT_ADMIN));
         }

         if (target.containsKey(SUBJECT_CLIENT)) {
             return getClientConverter().fromJSON(target);
         }
         return null;
    }

    public static JSON getContent(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        Object object = api.get(KEYS_CONTENT);
        if(object == null) return null;
        if(object instanceof JSONObject){return (JSONObject)object;}
        if(object instanceof JSONArray){return (JSONArray)object;}
        throw new IllegalArgumentException("Error: content is not json but of type " + object.getClass().getSimpleName());
    }
    public static int getMethodValue(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject action = api.getJSONObject(KEYS_ACTION);

        if (action.getString(KEYS_METHOD).equals(ACTION_ADD)) return ACTION_ADD_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_APPROVE)) return ACTION_APPROVE_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_UNAPPROVE)) return ACTION_UNAPPROVE_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_CREATE)) return ACTION_CREATE_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_EXECUTE)) return ACTION_EXECUTE_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_GET)) return ACTION_GET_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_LIST)) return ACTION_LIST_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_REMOVE)) return ACTION_REMOVE_VALUE;
        if (action.getString(KEYS_METHOD).equals(ACTION_SET)) return ACTION_SET_VALUE;

        return ACTION_UNKNOWN_VALUE;

    }

    public static Action getMethod(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject action = api.getJSONObject(KEYS_ACTION);

        if (action.getString(KEYS_METHOD).equals(ACTION_ADD)) return new ActionAdd();
        if (action.getString(KEYS_METHOD).equals(ACTION_APPROVE)) return new ActionApprove();
        if (action.getString(KEYS_METHOD).equals(ACTION_CREATE)) return new ActionCreate();
        if (action.getString(KEYS_METHOD).equals(ACTION_EXECUTE)) return new ActionExecute();
        if (action.getString(KEYS_METHOD).equals(ACTION_GET)) return new ActionGet();
        if (action.getString(KEYS_METHOD).equals(ACTION_LIST)) return new ActionList();
        if (action.getString(KEYS_METHOD).equals(ACTION_REMOVE)) return new ActionRemove();
        if (action.getString(KEYS_METHOD).equals(ACTION_SET)) return new ActionSet();

        return null;
    }

    public static int getTypeValue(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject action = api.getJSONObject(KEYS_ACTION);
        if (action.getString(KEYS_TYPE).equals(TYPE_ATTRIBUTE)) return TYPE_ATTRIBUTE_VALUE;
        if (action.getString(KEYS_TYPE).equals(TYPE_PERMISSION)) return TYPE_PERMISSION_VALUE;
        if (action.getString(KEYS_TYPE).equals(TYPE_ADMIN)) return TYPE_ADMIN_VALUE;
        if (action.getString(KEYS_TYPE).equals(TYPE_CLIENT)) return TYPE_CLIENT_VALUE;
        return TYPE_UNKNOWN_VALUE;

    }
    public static Type getType(JSONObject json) {
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject action = api.getJSONObject(KEYS_ACTION);
        if (action.getString(KEYS_TYPE).equals(TYPE_ATTRIBUTE)) return new TypeAttribute();
        if (action.getString(KEYS_TYPE).equals(TYPE_PERMISSION)) return new TypePermission();
        if (action.getString(KEYS_TYPE).equals(TYPE_ADMIN)) return new TypeAdmin();
        if (action.getString(KEYS_TYPE).equals(TYPE_CLIENT)) return new TypeClient();
        return null;
    }
}
