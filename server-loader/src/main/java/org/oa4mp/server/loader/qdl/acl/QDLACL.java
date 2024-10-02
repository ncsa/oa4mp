package org.oa4mp.server.loader.qdl.acl;

import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.exceptions.QDLIllegalAccessException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLMetaModule;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.Constant;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import net.sf.json.JSONObject;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * <H2>ACL Use</H2>
 * <p>Access Control Lists for QDL Scripts in OA4MP. You may do </p>
 * <ul>
 *     <li>acl_reject(id|id.) - blacklist these</li>
 *     <li>acl_add(id|id.) - allow access for the ids.</li>
 * </ul>
 * <p>Note that you may specify either client ids individually,  admin IDs. or * (to allow
 * unlimited access for, e.g., some library that is widely used). Setting an admin id
 * will allow all clients managed by the admin to have access.
 * </p>
 * <p>Created by Jeff Gaynor<br>
 * on 1/25/21 at  7:44 AM
 */
public class QDLACL implements QDLMetaModule {


    public static String ACL_REJECT_NAME = "acl_blacklist";

    public class ACLReject implements QDLFunction {
        @Override
        public String getName() {
            return ACL_REJECT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            acceptOrReject(objects, state, getName(), false);
            return null;
        }

        @Override

        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id | id.{,fail_on_bad_ids}) block access for this object or objects, AKA blacklist them.");
            doxx.add("if fail_on_bad_ids is true, then check each id to ensure it is valid and if not, throw an  exception.");
            doxx.add("   fail_on_bad_ids default is false.");
            return null;
        }
    }
public class ACLReject2 extends ACLReject{
    @Override
    public String getName() {
        return "blacklist";
    }
}
    public static String ADD_TO_ACL_NAME = "acl_add";

    protected Boolean acceptOrReject(Object[] objects,
                                     State state,
                                     String name,
                                     boolean accept // accept or reject refers to which method invoked this: add or blacklist
    ) {
        if (!(state instanceof OA2State)) {
            throw new IllegalArgumentException("Error: This requires an OA2State object.");
        }
        OA2State oa2State = (OA2State) state;
        if (objects.length == 0) {
            throw new IllegalArgumentException("Error: " + name + " requires an argument");
        }
        List<Object> ids;
        switch (Constant.getType(objects[0])) {
            case Constant.STEM_TYPE:
                ids = ((QDLStem) objects[0]).getQDLList().toJSON();
                break;
            case Constant.STRING_TYPE:
                ids = new ArrayList<>();
                ids.add((String) objects[0]);
                break;
            default:
                throw new IllegalArgumentException("Error: " + name + " requires a string or stem as its argument");

        }
        // Fix CIL-1668
        boolean failOnBadIds = false;
        if (objects.length == 2) {
            if (!(objects[1] instanceof Boolean)) {
                throw new IllegalArgumentException("Error: " + name + " requires a boolean as its second argument");
            }
            failOnBadIds = (Boolean) objects[1];
        }
        ArrayList<String> badIds = new ArrayList<>();
        for (Object id : ids) {
            Identifier identifier;
            if (!(id instanceof String)) {
                throw new IllegalArgumentException("Error: '" + id + "' is not a valid identifier");
            }
            try {
                URI uri = URI.create((String) id);
                identifier = BasicIdentifier.newID(uri);
            } catch (Throwable t) {
                if (failOnBadIds) {
                    throw new IllegalArgumentException("Error: " + name + " requires a valid identifier");
                } else {
                    badIds.add(id.toString());
                    continue;
                }
                // can get exception here from bad id
            }
            boolean isClientID = oa2State.getOa2se().getClientStore().containsKey(identifier);
            boolean isAdminID = oa2State.getOa2se().getAdminClientStore().containsKey(identifier);
            if (isAdminID && isClientID) {
                throw new NFWException("Error: There is a regular client and an admin client with the same id '" + identifier.toString() + "'");
            }
            if (!isAdminID && !isClientID) {
                if (failOnBadIds) {
                    throw new QDLIllegalAccessException(" There is a no such client with id '" + identifier.toString() + "'. Access denied.");
                } else {
                    badIds.add(identifier.toString());
                }
            }
            if (accept) {
                oa2State.getAclList().add(identifier);
            } else {
                oa2State.getAclBlackList().add(identifier);
            }
        }
        if (0 < badIds.size()) {
            StringBuilder sb = new StringBuilder(badIds.size() + 2);
            sb.append("[");
            boolean firstLoop = true;
            for (String s : badIds) {
                if (firstLoop) {
                    firstLoop = false;
                    sb.append(s);
                } else {
                    sb.append(", " + s);
                }
            }
            sb.append("]");
            oa2State.getOa2se().getMyLogger().warn("failed to add the following IDs to the ACLs :" + sb);
        }

        return Boolean.TRUE;
    }


    public class AddToACL implements QDLFunction {
        @Override
        public String getName() {
            return ADD_TO_ACL_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            return acceptOrReject(objects, state, getName(), true);
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id | id.{,fail_on_bad_ids}) add to the access control list for this object");
            if (argCount == 1) {
                doxx.add("Accepts either a string or a list of them.");
                doxx.add("if fail_on_bad_ids is true, then check each id to ensure it is valid and if not, throw an  exception.");
                doxx.add("   fail_on_bad_ids default is false.");
                doxx.add("This sets the admin_id or client_id. If an admin id, then any client has access ");
                doxx.add("to this object. If a client id, then precisely that client is allowed");
            }

            return doxx;
        }
    }
   public class AddToACL2 extends AddToACL {
       @Override
       public String getName() {
           return "add";
       }
   }
    public static String CHECK_ACL_NAME = "acl_check";
    public static Identifier ACL_ACCEPT_ALL = BasicIdentifier.newID("*");


    public class CheckACL implements QDLFunction {
        @Override
        public String getName() {
            return CHECK_ACL_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{0};
        }

        @Override
        public Object evaluate(Object[] objects, State state) {
            if (!(state instanceof OA2State)) {
                throw new IllegalArgumentException(" This requires an OA2State object.");
            }

            OA2State oa2State = (OA2State) state;
            // Check blacklist first

            if (oa2State.getAclBlackList().contains(oa2State.getClientID())) {
                // Full stop.
                throw new QDLIllegalAccessException(" client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
            }
            for (Identifier adminID : oa2State.getAdminIDs()) {
                if (oa2State.getAclBlackList().contains(adminID)) {
                    throw new QDLIllegalAccessException(" client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
                }
            }
            if (oa2State.getAclList().isEmpty()) {
                if (oa2State.isStrictACLs()) {
                    throw new QDLIllegalAccessException(" client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
                }
                return Boolean.FALSE;
            }
            if (oa2State.getAclList().contains(ACL_ACCEPT_ALL)) {
                return Boolean.TRUE;
            }
            // Direct check.
            if (oa2State.getAclList().contains(oa2State.getClientID())) {
                return Boolean.TRUE;
            }
            for (Identifier adminID : oa2State.getAdminIDs()) {
                if (oa2State.getAclList().contains(adminID)) {
                    return Boolean.TRUE;
                }
            }
            throw new QDLIllegalAccessException("Error: client '" + oa2State.getClientID() + "' does not have permission to access this resource.");

        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + " check the current access list. If there is no such entry, an illegal access is triggered.");
            doxx.add("See also: " + ADD_TO_ACL_NAME);
            return doxx;
        }
    }

    /**
     * This uses the short name for this so it can be used with better naming by
     * the new module systsm, e.g. acl#add rather than acl#acl_add
     */
    public class CheckACL2 extends CheckACL {
        @Override
        public String getName() {
            return "check";
        }
    }

    @Override
    public JSONObject serializeToJSON() {
        return null;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {

    }
}
