package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:11 PM
 */
public class GroupElement {
    public GroupElement(String name, int id) {
        this.id = id;
        this.name = name;
    }

    public GroupElement(String name) {
        this.name = name;
    }
    public GroupElement(JSONObject json) {
        fromJSON(json);
    }

    String name;
    int id = -1;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public JSONObject toJSON() {
        JSONObject json = new JSONObject();
        json.put("name", getName());
        if (-1 < id) {
            json.put("id", getId());
        }
        return json;
    }

    public void fromJSON(JSONObject json) {
        setName(json.getString("name"));
        if (json.containsKey("id")) {
            setId(json.getInt("id"));
        }
    }
}
