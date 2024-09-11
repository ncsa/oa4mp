package org.oa4mp.server.loader.oauth2.claims;

import net.sf.json.JSONObject;

import static org.oa4mp.server.loader.oauth2.claims.Groups.*;

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
        json.put(GROUP_ENTRY_NAME, getName());
        if (-1 < id) {
            json.put(GROUP_ENTRY_ID, getId());
        }
        return json;
    }

    public void fromJSON(JSONObject json) {
        setName(json.getString(GROUP_ENTRY_NAME));
        if (json.containsKey(GROUP_ENTRY_ID)) {
            setId(json.getInt(GROUP_ENTRY_ID));
        }
    }

    @Override
    public String toString() {
        return "GroupElement{" +
                GROUP_ENTRY_ID + "=" + id +
                ", " + GROUP_ENTRY_NAME+"='" + name + '\'' +
                '}';
    }
}
