package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.*;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  10:24 AM
 */
public class SATFactory implements SAT {
    static AdminClientConverter<? extends AdminClient> getACConverter(){
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

public static Identifier getIdentifier(JSONObject json){
        JSONObject id = json.getJSONObject(SAT.KEYS_ID);
        return BasicIdentifier.newID(id.getString("id"));

    }
    public static String getSecret(JSONObject json){
        JSONObject id = json.getJSONObject(SAT.KEYS_ID);
        return id.getString("secret");

    }


     public  static BaseClient getSubject(JSONObject json){
         JSONObject api = json.getJSONObject(KEYS_API);
         JSONObject subject = api.getJSONObject(KEYS_SUBJECT);
         if(subject.containsKey(SUBJECT_ADMIN)){
                return getACConverter().fromJSON(subject.getJSONObject(SUBJECT_ADMIN));
         }

         if(subject.containsKey(SUBJECT_CLIENT)){
             return getClientConverter().fromJSON(subject);
         }
         return null;
     }

    public static JSONObject getTarget(JSONObject json){
         JSONObject api = json.getJSONObject(KEYS_API);
         JSONObject target = api.getJSONObject(KEYS_TARGET);
          return target;
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

    public static Type getType(JSONObject json){
        JSONObject api = json.getJSONObject(KEYS_API);
        JSONObject action = api.getJSONObject(KEYS_ACTION);
        if (action.getString(KEYS_TYPE).equals(TYPE_ATTRIBUTE)) return new TypeAttribute();
        if (action.getString(KEYS_TYPE).equals(TYPE_PERMISSION)) return new TypePermission();
        if (action.getString(KEYS_TYPE).equals(TYPE_ADMIN)) return new TypeAdmin();
        if (action.getString(KEYS_TYPE).equals(TYPE_CLIENT)) return new TypeClient();
      return null;
    }
}
