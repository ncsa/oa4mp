package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.HashMap;

/**
 * A model for groups that are returned by various scope handlers. This is modelled
 * by a JSON array of {@link GroupElement} objects.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:11 PM
 */
public class Groups extends HashMap<String, GroupElement> {
    public static String GROUP_ENTRY_NAME = "name";
    public static String GROUP_ENTRY_ID = "id";
    public void put(GroupElement groupElement) {
        super.put(groupElement.getName(), groupElement);
    }

    public JSONArray toJSON() {
        JSONArray array = new JSONArray();
        for (String key : keySet()) {
            GroupElement groupElement = get(key);
            array.add(groupElement.toJSON());
        }
        return array;
    }

    /**
     * This presupposes that the elements of the array are normalized in the form {"name":name,"id":id}
     * rather than the raw form that comes froma  lot of LDAPs.
     * @param array
     */
    public void fromJSON(JSONArray array) {
        for (Object obj : array) {
            if (obj instanceof JSONObject) {
                GroupElement groupElement = new GroupElement((JSONObject) obj);
                put(groupElement);
            }
        }
    }
}
