package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.kordamp.json.JSONObject;
import org.oa4mp.server.admin.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionKeys;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/17 at  3:11 PM
 */
public class OA2PermissionCommands extends OA4MPStoreCommands {
    public OA2PermissionCommands(CLIDriver driver, String defaultIndent, Store store) throws Throwable {
        super(driver, defaultIndent, store);
    }

    public OA2PermissionCommands(CLIDriver driver, Store store) throws Throwable {
        super(driver, store);
    }

    protected PermissionsStore getPStore() {
        return (PermissionsStore) getStore();
    }

     @Override
    public String getName() {
        return "permissions";
    }

    @Override
    protected String format(Identifiable identifiable) {
        return null;
    }
    protected String format(Identifiable identifiable, int offset ) {
        Permission p = (Permission) identifiable;
        HashMap<String, String> map = new HashMap<>();
        // Well-formed permissions always have these, but it is possible something went wrong
        // in which case, show the bad ones so they can be expunged.
       map.put("admin", p.getAdminID() == null ? "---" : p.getAdminID().toString());
       map.put("client", p.getClientID() == null ? "---" : p.getClientID().toString());
       map.put("ersatz id = ", p.getErsatzChain() == null ? "---" : p.getErsatzChain().toString());
       map.put("identifier", p.getIdentifier().toString());
       List<String> pp = StringUtils.formatMap(map,null, false,false, 3,100);
       String out = "";
       boolean isFirst = true;
       String blanks = StringUtils.getBlanks(offset+4);
       for(String x : pp){
           out = out + (isFirst?"":("\n" + blanks)) + x;
           if (isFirst) isFirst = false;
       }
       return out;
    }
    protected String OLDformat(Identifiable identifiable) {
        Permission p = (Permission) identifiable;
        String output = "admin=" + p.getAdminID() + ", client=" + p.getClientID() + ", ersatz id=" + p.getErsatzChain() + ", id=" + p.getIdentifierString();
        return output;
    }


    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        Permission p = (Permission) identifiable;
        PermissionKeys keys = (PermissionKeys)getSerializationKeys();
        String input;
        if (p.getClientID() == null) {
            input = getPropertyHelp(keys.clientID(),"Enter new client id", "");

        } else {
            input = getPropertyHelp(keys.clientID(),"Enter new client id", p.getClientID().toString());
        }

        if (!isEmpty(input)) {
            p.setClientID(BasicIdentifier.newID(input));
        }
        if (p.getAdminID() == null) {
            input = getPropertyHelp(keys.adminID(),"Enter new admin id", "");

        } else {
            input = getPropertyHelp(keys.adminID(),"Enter new admin id", p.getAdminID().toString());
        }
        if (!isEmpty(input)) {
            p.setAdminID(BasicIdentifier.newID(input));
        }
        // For the next, the help is just general help for permissions rather than each permission.
        input = getPropertyHelp("permissions","set all permissions (y/n):", "y");
        if (!isEmpty(input)) {
            if (input.toLowerCase().equals("y")) {
                p.setApprove(true);
                p.setCreate(true);
                p.setDelete(true);
                p.setRead(true);
                p.setWrite(true);
            } else {
                p.setApprove(false);
                p.setCreate(false);
                p.setDelete(false);
                p.setRead(false);
                p.setWrite(false);
            }
        }
        return false;
    }

    @Override
    protected String columnHeader(int offset) {
        return super.columnHeader(offset);
    }

    protected void removeEntry(Identifiable identifiable, JSONObject json) {
        HashMap<String, Object> map = new HashMap();
        getPStore().getXMLConverter().toMap(identifiable, map);
        MapConverter mc = (MapConverter) getPStore().getXMLConverter();
        json.remove(mc.keys.identifier()); // don't let it change the identifier
        for(Object key : json.keySet()){
            map.remove(key);
        }
        Permission p = (Permission) mc.fromMap(map, identifiable);
        getPStore().save(p);

    }

    @Override
    public void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/permission_help.xml");
    }

    @Override
    public void change_id(InputLine inputLine) throws Throwable {
        say("Changing ids for permissions is not supported");
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        throw new UnsupportedOperationException("Not supported for permissions.");
    }
}
