package org.oa4mp.server.api.admin.permissions;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  12:09 PM
 */
public class PermissionKeys extends SerializationKeys {
    public PermissionKeys() {
        super();
        identifier("permission_id");
    }

    String adminID = "admin_id";
    String clientID = "client_id";
    String ersatzID = "ersatz_id";
    String substitute = "can_substitute";
    String readable = "can_read";
    String writable = "can_write";
    String canCreate = "can_create";
    String canRemove = "can_remove";
    String canApprove = "can_approve";

    /*
        If you change this, update the QDL store PermissionStemMC or you will break it!
     */
    public String ersatzID(String... x) {
        if (0 < x.length) ersatzID = x[0];
        return ersatzID;
    }
    public String substitute(String... x) {
        if (0 < x.length) substitute = x[0];
        return substitute;
    }

    public String adminID(String... x) {
        if (0 < x.length) adminID = x[0];
        return adminID;
    }

    public String clientID(String... x) {
        if (0 < x.length) clientID = x[0];
        return clientID;
    }

    public String readable(String... x) {
        if (0 < x.length) readable = x[0];
        return readable;
    }

    public String writeable(String... x) {
        if (0 < x.length) writable = x[0];
        return writable;
    }

    public String canCreate(String... x) {
        if (0 < x.length) canCreate = x[0];
        return canCreate;
    }

    public String canRemove(String... x) {
        if (0 < x.length) canRemove = x[0];
        return canRemove;
    }
    public String canApprove(String... x) {
        if (0 < x.length) canApprove= x[0];
        return canApprove;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(adminID());
        allKeys.add(canApprove());
        allKeys.add(canCreate());
        allKeys.add(canRemove());
        allKeys.add(clientID());
        allKeys.add(readable());
        allKeys.add(writeable());
        allKeys.add(ersatzID());
        allKeys.add(substitute());
        return allKeys;
    }
}
