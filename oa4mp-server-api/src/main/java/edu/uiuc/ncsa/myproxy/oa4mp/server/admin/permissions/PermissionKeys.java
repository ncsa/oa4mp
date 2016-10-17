package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/12/16 at  12:09 PM
 */
public class PermissionKeys extends SerializationKeys {
    String adminID = "adminID";
    String clientID = "clientID";
    String readable = "readable";
    String writable = "writeable";
    String canCreate = "canCreate";
    String canRemove = "canRemove";
    String canApprove = "canApprove";

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

}
