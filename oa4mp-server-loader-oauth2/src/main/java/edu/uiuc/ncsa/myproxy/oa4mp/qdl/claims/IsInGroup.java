package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.variables.StemVariable;

import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups.GROUP_ENTRY_NAME;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/20 at  7:52 AM
 */
public class IsInGroup implements QDLFunction {
    @Override
    public String getName() {
        return "in_group";
    }

    @Override
    public int[] getArgCount() {
        return new int[]{2};
    }

    @Override
    public Object evaluate(Object[] objects) {
        // First argument is a stem of groups. This is a list that has
        // stem elements of the form stem.name and stem.id. The name is the
        // name of the group.
        if (!(objects[0] instanceof StemVariable)) {
            throw new IllegalArgumentException("Error: The first argument of " + getName() + " must be a stem list of groups.");
        }
        StemVariable groups = (StemVariable) objects[0];
        if (!(objects[1] instanceof String)) {
            throw new IllegalArgumentException("Error: The second argument of " + getName() + " must be a string.");
        }
        String name = (String) objects[1];
        for (String key : groups.keySet()) {
            Object obj = groups.get(key);
            // two options, either they parsed it in to a group structure OR its just a raw string
            if (obj instanceof StemVariable) {
                StemVariable group = (StemVariable) obj;
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
    public QDLFunction getInstance() {
        return this;
    }

    @Override
    public List<String> getDocumentation() {
        return null;
    }
}
