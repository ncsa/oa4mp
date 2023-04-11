package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.GroupElement;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups;
import net.sf.json.JSONArray;

import java.io.Serializable;

/**
 * This takes a list of attributes from an LDAP handler and converts it into a regularized
 * group structure.
 * <p>Created by Jeff Gaynor<br>
 * on 3/1/18 at  4:32 PM
 */
public class GroupHandler implements Serializable {
    /**
     * The most basic incarnation. This assumes that the raw JSON is just an array of
     * group names (e.g. ["grp0","grp1",...])  with no special structure.
     * @param jsonArray
     * @return
     */
     public Groups parse(JSONArray jsonArray){
         Groups groups = new Groups();
           for(Object x : jsonArray){
              if(x instanceof String){
                  GroupElement g = new GroupElement(String.valueOf(x));
                  groups.put(g);
              }
           }
         return groups;
     }
}
