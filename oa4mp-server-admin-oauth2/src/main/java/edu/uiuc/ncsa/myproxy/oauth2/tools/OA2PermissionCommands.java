package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;

import java.util.HashMap;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/7/17 at  3:11 PM
 */
public class OA2PermissionCommands extends StoreCommands2 {
    public OA2PermissionCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public OA2PermissionCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    protected PermissionsStore getPStore() {
        return (PermissionsStore) getStore();
    }

    @Override
    public void extraUpdates(Identifiable identifiable) {

    }

    @Override
    public String getName() {
        return "permissions";
    }

    @Override
    protected String format(Identifiable identifiable) {
        Permission p = (Permission) identifiable;
        String output = "Permission: admin=" + p.getAdminID() + ", client=" + p.getClientID() + ", id=" + p.getIdentifierString();
        return output;
    }

    @Override
    public boolean update(Identifiable identifiable) {
        Permission p = (Permission) identifiable;
        String input;
        if (p.getClientID() == null) {
            input = getInput("Enter new client id", "");

        } else {
            input = getInput("Enter new client id", p.getClientID().toString());
        }

        if (!isEmpty(input)) {
            p.setClientID(BasicIdentifier.newID(input));
        }
        if (p.getAdminID() == null) {
            input = getInput("Enter new admin id", "");

        } else {
            input = getInput("Enter new admin id", p.getAdminID().toString());
        }
        if (!isEmpty(input)) {
            p.setAdminID(BasicIdentifier.newID(input));
        }
        input = getInput("set all permissions (y/n):", "y");
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
    protected void longFormat(Identifiable identifiable) {
        Permission p = (Permission) identifiable;
        sayi("client id=" + p.getClientID());
        sayi("admin id=" + p.getAdminID());
        sayi("can approve?=" + p.isApprove());
        sayi("can read?=" + p.isRead());
        sayi("can write?=" + p.isWrite());
        sayi("can delete?=" + p.isDelete());
        sayi("can create?=" + p.isCreate());

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
}
