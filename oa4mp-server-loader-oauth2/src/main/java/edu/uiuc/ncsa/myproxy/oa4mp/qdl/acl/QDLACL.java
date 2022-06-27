package edu.uiuc.ncsa.myproxy.oa4mp.qdl.acl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.scripting.OA2State;
import edu.uiuc.ncsa.qdl.exceptions.QDLIllegalAccessException;
import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLModuleMetaClass;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.Constant;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;

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
public class QDLACL implements QDLModuleMetaClass {


    public static String ACL_REJECT_NAME = "acl_reject";

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
            doxx.add(getName() + "(id | id.) block for this object or objects. AKA blacklist them.");

            return null;
        }
    }

    public static String ADD_TO_ACL_NAME = "acl_add";

    protected Boolean acceptOrReject(Object[] objects, State state, String name, boolean accept) {
        if (!(state instanceof OA2State)) {
            throw new IllegalArgumentException("Error: This requires an OA2State object.");
        }
        OA2State oa2State = (OA2State) state;
        if (objects.length != 1) {
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
        for (Object id : ids) {
            Identifier identifier;
            try {
                if (!(id instanceof String)) {
                    throw new IllegalArgumentException("Error: '" + id + "' is not a valid identifier");
                }
                URI uri = URI.create((String) id);
                identifier = BasicIdentifier.newID(uri);
                boolean isClientID = oa2State.getOa2se().getClientStore().containsKey(identifier);
                boolean isAdminID = oa2State.getOa2se().getAdminClientStore().containsKey(identifier);
                if (isAdminID && isClientID) {
                    throw new NFWException("Error: There is a regular client and an admin client with the same id '" + identifier.toString() + "'");
                }
                if (!isAdminID && !isClientID) {
                    throw new QDLIllegalAccessException("Error: There is a no such client with id '" + identifier.toString() + "'. Access denied.");
                }
                if (accept) {
                    oa2State.getAclList().add(identifier);
                } else {
                    oa2State.getAclBlackList().add(identifier);
                }

            } catch (Throwable t) {
                throw new IllegalArgumentException("Error: " + name + " requires a valid identifier");
            }

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
            doxx.add(getName() + "(id | id.) add to the access control list for this object");
            if (argCount == 1) {
                doxx.add("Accepts either a string or a list of them.");
                doxx.add("This sets the admin_id or client_id. If an admin id, then any client has access ");
                doxx.add("to this object. If a client id, then precisely that client is allowed");
            }

            return doxx;
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
                throw new IllegalArgumentException("Error: This requires an OA2State object.");
            }

            OA2State oa2State = (OA2State) state;
            // Check blacklist first

            if (oa2State.getAclBlackList().contains(oa2State.getClientID())) {
                // Full stop.
                throw new QDLIllegalAccessException("Error: client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
            }
            for (Identifier adminID : oa2State.getAdminIDs()) {
                if (oa2State.getAclBlackList().contains(adminID)) {
                    throw new QDLIllegalAccessException("Error: client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
                }
            }
            if (oa2State.getAclList().isEmpty()) {
                if (oa2State.isStrictACLs()) {
                    throw new QDLIllegalAccessException("Error: client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
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
}
