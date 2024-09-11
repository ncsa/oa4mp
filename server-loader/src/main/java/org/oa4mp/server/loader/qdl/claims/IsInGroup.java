package org.oa4mp.server.loader.qdl.claims;

import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

import java.util.ArrayList;
import java.util.List;

import static org.oa4mp.server.loader.oauth2.claims.Groups.GROUP_ENTRY_NAME;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/20 at  7:52 AM
 */
public class IsInGroup implements QDLFunction {

    public static final String IN_GROUP_NAME = "in_group";

    @Override
    public String getName() {
        return IN_GROUP_NAME;
    }

    @Override
    public int[] getArgCount() {
        return new int[]{2};
    }

    @Override
    public Object evaluate(Object[] objects, State state) {
        // First argument is a stem of groups. This is a list that has
        // stem elements of the form stem.name and stem.id. The name is the
        // name of the group.

        // Much better checks here. Exceptions are very helpful in debugging, but hits
        // a lot of edge cases (empty list, e.g.)
        if (objects == null) {
          //  throw new IllegalArgumentException("Error: no arguments for " + getName());
            return Boolean.FALSE;
        }
        if (objects.length != 2) {
            throw new IllegalArgumentException(" This function requires two arguments, a stem and a string.");
        }

        if (objects[0]==null) {
            return Boolean.FALSE;
        }
        if(!(objects[0] instanceof QDLStem)){
            // This indicates that something wrong was passed, so flag it as a bona fide error.
            throw new IllegalArgumentException(" The first argument of " + getName() + " must be a stem list of groups.");
        }
        QDLStem groups = (QDLStem) objects[0];
        if(groups.size() == 0){
            return Boolean.FALSE;
        }
        if (objects[1] == null | !(objects[1] instanceof String)) {
            throw new IllegalArgumentException(" The second argument of " + getName() + " must be a string.");
        }
        String name = (String) objects[1];
        for (Object key : groups.keySet()) {
            Object obj = groups.get(key);
            // two options, either they parsed it in to a group structure OR its just a raw string
            if (obj instanceof QDLStem) {
                QDLStem group = (QDLStem) obj;
                if (group.containsKey(GROUP_ENTRY_NAME) && group.getString(GROUP_ENTRY_NAME).equals(name)) {
                    return Boolean.TRUE;
                }
            } else {
                // Failing that, try to process it as a string.
                if (obj.toString().equals(name)) return Boolean.TRUE;
            }
        }
        return Boolean.FALSE;
    }


    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> docs = new ArrayList<>();
        docs.add("Deprecated. Use in_group2 which can process stems. Note the arguments are swapped there.");
        docs.add(getName() + "(groups., group_name) - checks if a group_name is in the given set of groups.");
        docs.add("This will work on either a flat list of group names or an isMemberOf structure,");
        docs.add("where each entry is of the form {name,id}");
        return docs;
    }
}
