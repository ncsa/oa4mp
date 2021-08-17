package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.StemVariable;

import java.util.ArrayList;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.Groups.GROUP_ENTRY_NAME;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/20 at  7:52 AM
 */
public class IsInGroup2 implements QDLFunction {

    public static final String IN_GROUP_NAME = "in_group2";

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
        // First argument is a either a group (single string) or list of them.
        // Second argument is the stem of groups. This is a list that has
        // stem elements of the form stem.name and stem.id. The name is the
        // name of the group.

        // Much better checks here. Exceptions are very helpful in debugging, but hits
        // a lot of edge cases (empty list, e.g.)
        if (objects == null) {
            //  throw new IllegalArgumentException("Error: no arguments for " + getName());
            return Boolean.FALSE;
        }

        if (objects.length != 2) {
            throw new IllegalArgumentException("Error: This function requires two arguments, a stem and a string.");
        }
        if (objects[0] == null || (!(objects[0] instanceof StemVariable) && !(objects[0] instanceof String))) {
            throw new IllegalArgumentException("Error: The first argument of " + getName() + " must be a string or stem of them.");
        }
        if (objects[1] == null) {
            // only way to get a java null is to have an undefined variable.
            throw new IllegalArgumentException("Error: Undefined second argument for " + getName());
        }

        if (!(objects[1] instanceof StemVariable)) {
            // This indicates that something wrong was passed, so flag it as a bona fide error.
            throw new IllegalArgumentException("Error: The second argument of " + getName() + " must be a stem list of groups.");
        }
        StemVariable groups = (StemVariable) objects[1];
        if (groups.size() == 0) {
            return Boolean.FALSE;
        }

        StemVariable groupNames;
        boolean isScalar = objects[0] instanceof String;
        if (isScalar) {
            groupNames = new StemVariable();
            groupNames.listAppend(objects[0]);

        } else {
            groupNames = (StemVariable) objects[0];
        }
        StemVariable result = new StemVariable();
        for (String keys : groupNames.keySet()) {
            String name = groupNames.getString(keys);
            Boolean rValue = Boolean.FALSE;
            for (String key : groups.keySet()) {
                Object obj = groups.get(key);
                // two options, either they parsed it in to a group structure OR its just a raw list of strings
                if (obj instanceof StemVariable) {
                    StemVariable group = (StemVariable) obj;
                    if (group.containsKey(GROUP_ENTRY_NAME) && group.getString(GROUP_ENTRY_NAME).equals(name)) {
                        rValue = Boolean.TRUE;
                        break;
                    }
                } else {
                    if(!(obj instanceof String)){
                        throw new IllegalArgumentException("Error: unrecognized element in group.'" + obj + "'");
                    }
                    // Failing that, try to process it as a string.
                    if (obj.toString().equals(name)) {
                        rValue = Boolean.TRUE;
                        break;
                    }
                }
            }
                result.put(keys, rValue);
        }
        if (isScalar) {
            return result.get(0L);
        }
        return result;

    }


    @Override
    public List<String> getDocumentation(int argCount) {
        List<String> docs = new ArrayList<>();
        docs.add(getName() + "(group_name, groups.) - checks if a group_name is in the given set of groups.");
        docs.add("the first argument is either a string with the group name or a stem of group names.");
        docs.add("The result is always left conformable.");
        docs.add("This will work on either a flat list of groups.  or an isMemberOf structure,");
        docs.add("where each entry is of the form {name,id}");
        docs.add("E.g.");
        docs.add("Example where the groups. is a group structure with name and id");
        docs.add("   groups. := [{'name':'test0','id':123}, {'name':'test1','id':234}, {'name':'test2','id':345}, {'name':'test3','id':456}];");
        docs.add("   " + getName() + "(['test0', 'foo'], groups.)");
        docs.add("[true,false]");
        docs.add("E.g.");
        docs.add("Example to show this works with a scalar and returns a scalar.");
        docs.add("   " + getName() + "('test2', groups.)");
        docs.add("true");
        docs.add("E.g.");
        docs.add("Example where the groups. is a flat list of names -- which can happen too.");
        docs.add("   groups2. := ['test0', 'test1', 'test2', 'test3'];");
        docs.add("   "+ getName() + "(['test0', 'foo'], groups.)");
        docs.add("[true,false]");
        docs.add("\nFinal note: If group_name is a list, the result is a list, if it is a stem");
        docs.add("the result is a stem as well. This makes it easy to use with mask and other functions.");
        return docs;
    }
}
