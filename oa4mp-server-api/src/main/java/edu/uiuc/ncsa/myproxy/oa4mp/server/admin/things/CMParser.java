package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

import net.sf.json.JSONObject;

/**
 * Parses JSON strings into objects for the Client Manager.
 * <p>Created by Jeff Gaynor<br>
 * on 11/10/16 at  4:39 PM
 */
public class CMParser {
    public Request parser(String rawJson){
        JSONObject top =  JSONObject.fromObject(rawJson);
        JSONObject api = top.getJSONObject(SAT.KEYS_API);
        JSONObject subject = api.getJSONObject(SAT.KEYS_SUBJECT);
        JSONObject action = api.getJSONObject(SAT.KEYS_ACTION);
        JSONObject target = api.getJSONObject(SAT.KEYS_TARGET);
        JSONObject content = api.getJSONObject(SAT.KEYS_CONTENT);

         return null;
    }
}
