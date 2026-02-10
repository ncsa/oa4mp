package org.oa4mp.server.loader.qdl.acl;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.oa4mp.server.loader.qdl.scripting.OA2State;
import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.exceptions.QDLIllegalAccessException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.extensions.QDLMetaModule;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.Constant;
import org.qdl_lang.variables.values.BooleanValue;
import org.qdl_lang.variables.values.QDLValue;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;

import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

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

    public TreeSet<String> getWhiteList() {
        if (whiteList == null) {
            whiteList = new TreeSet<>();
        }
        return whiteList;
    }

    public void setWhiteList(TreeSet<String> whiteList) {
        this.whiteList = whiteList;
    }

    public TreeSet<String> getBlackList() {
        if (blackList == null) {
            blackList = new TreeSet<>();
        }
        return blackList;
    }

    public void setBlackList(TreeSet<String> blackList) {
        this.blackList = blackList;
    }

    TreeSet<String> whiteList = null;
    TreeSet<String> blackList = null;

    public boolean hasWhiteList() {
        return whiteList != null;
    }

    public boolean hasBlackList() {
        return blackList != null;
    }

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
        public QDLValue evaluate(QDLValue[] objects, State state) {
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

    public class ACLReject2 extends ACLReject {
        @Override
        public String getName() {
            return "blacklist";
        }
    }

    public static String ADD_TO_ACL_NAME = "acl_add";

    protected Boolean acceptOrReject(QDLValue[] qdlValues,
                                     State state,
                                     String name,
                                     boolean accept // accept or reject refers to which method invoked this: add or blacklist
    ) {
        if (!(state instanceof OA2State)) {
            throw new IllegalArgumentException("Error: ACLs not supported in this environment.");
        }
        OA2State oa2State = (OA2State) state;
        if (qdlValues.length == 0) {
            throw new IllegalArgumentException("Error: " + name + " requires an argument");
        }
        JSONArray ids;
        switch (qdlValues[0].getType()) {
            case Constant.STEM_TYPE:
                ids = qdlValues[0].asStem().getQDLList().toJSON();
                break;
            case Constant.STRING_TYPE:
                ids = new JSONArray();
                ids.add(qdlValues[0].asString());
                break;
            default:
                throw new BadArgException("Error: " + name + " requires a string or stem as its argument",0);

        }
        // Fix CIL-1668
        boolean failOnBadIds = false;
        if (qdlValues.length == 2) {
            if (!(qdlValues[1].isBoolean())) {
                throw new BadArgException("Error: " + name + " requires a boolean as its second argument",1);
            }
            failOnBadIds = qdlValues[1].asBoolean();
        }
        ArrayList<String> badIds = new ArrayList<>();
        for (Object id : ids) {
            Identifier identifier;
            if (!(id instanceof String)) {
                throw new IllegalArgumentException("Error: '" + id + "' is not a string");
            }
            try {
                URI uri = URI.create((String) id);
                identifier = BasicIdentifier.newID(uri);
            } catch (Throwable t) {
                if (failOnBadIds) {
                    throw new IllegalArgumentException("Error: " + name + " requires a valid identifier");
                } else {
                    badIds.add(id.toString());
                    // Fix https://github.com/ncsa/oa4mp/issues/286
                    oa2State.getOa2se().getMyLogger().warn("ACL - invalid identifier (" + t.getMessage() + "): " + id);
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
                    // Fix https://github.com/ncsa/oa4mp/issues/286
                    oa2State.getOa2se().getMyLogger().warn("ACL - invalid client :" + identifier);
                    badIds.add(identifier.toString());
                }
            }
            if (accept) {
                getWhiteList().add(identifier.toString());
                //   oa2State.getAclList().add(identifier);
            } else {
                getBlackList().add(identifier.toString());
                //    oa2State.getAclBlackList().add(identifier);
            }
        }

/* Don't need to return list, just log bad ids above.
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
*/

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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            return asQDLValue(acceptOrReject(objects, state, getName(), true));
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(id | id.{,fail_on_bad_ids}) add to the access control list for this object");
            if (argCount == 1) {
                doxx.add("Accepts either a string or a list of them.");
                doxx.add("if fail_on_bad_ids is true, then check each id to ensure it is valid and if not, throw an  exception.");
                doxx.add("   fail_on_bad_ids default is false, then this call will silently ignore bad ids.");
                doxx.add("   This can be used if there are possibly unknown client IDs or the syntax is bad.");
                doxx.add("   Note that this id is not added, so in fact, it allows processing to continue rather than stopping the whole system,");
                doxx.add("   but does not alter the security one iota. Check the logs if there is a question.");
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
        public QDLValue evaluate(QDLValue[] objects, State state) {
            if (!(state instanceof OA2State)) {
                throw new IllegalArgumentException(" This requires an OA2State object.");
            }

            OA2State oa2State = (OA2State) state;
            // Check blacklist first
            if (!oa2State.getAclBlackList().isEmpty()) {
                for (Identifier id : oa2State.getAclBlackList()) {
                    getBlackList().add(id.toString());
                }
            }
            if (!oa2State.getAclList().isEmpty()) {
                for (Identifier id : oa2State.getAclList()) {
                    getWhiteList().add(id.toString());
                }
            }
            if (getBlackList().contains(oa2State.getClientID().toString())) {
                // Full stop.
                throw new QDLIllegalAccessException(" client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
            }
            for (Identifier adminID : oa2State.getAdminIDs()) {
                if (getBlackList().contains(adminID.toString())) {
                    throw new QDLIllegalAccessException(" admin '" + adminID + "' does not have permission to access this resource.");
                }
            }
            if (getWhiteList().isEmpty()) {
                if (oa2State.isStrictACLs()) {
                    throw new QDLIllegalAccessException(" client '" + oa2State.getClientID() + "' does not have permission to access this resource.");
                }
                return BooleanValue.False;
            }
            if (getWhiteList().contains(ACL_ACCEPT_ALL.toString())) {
                return BooleanValue.True;
            }
            // Direct check.
            if (getWhiteList().contains(oa2State.getClientID().toString())) {
                return BooleanValue.True;
            }
            for (Identifier adminID : oa2State.getAdminIDs()) {
                if (getWhiteList().contains(adminID.toString())) {
                    return BooleanValue.True;
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
        JSONObject json = new JSONObject();
        if (hasBlackList()) {
            JSONArray array = new JSONArray();
            array.addAll(getBlackList());
            json.put("blacklist", array);
        }
        if (hasWhiteList()) {
            JSONArray array = new JSONArray();
            array.addAll(getWhiteList());
            json.put("whitelist", array);
        }
        return json;
    }

    @Override
    public void deserializeFromJSON(JSONObject jsonObject) {
        if (jsonObject.has("blacklist")) {
            getBlackList().addAll(jsonObject.getJSONArray("blacklist"));
        }
        if (jsonObject.has("whitelist")) {
            getWhiteList().addAll(jsonObject.getJSONArray("whitelist"));
        }
    }
}
