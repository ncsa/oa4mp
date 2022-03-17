package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.delegation.storage.BaseClientKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:53 PM
 */
public class AdminClientKeys extends BaseClientKeys {
    public AdminClientKeys() {
        super();
        identifier("admin_id");
        secret("secret");
    }
    String allowQDL = "allow_qdl";
    String config = "config";
    String issuer = "issuer";
    String maxClients = "max_clients";
    String notifyOnNewClientCreate="new_client_notify";
    String vo="vo";
    String voURI="vo_uri";
    String listUsers = "list_users";
    String listUsersInOtherClients = "list_users_other_clients";

    public String listUsers(String... x) {
        if (0 < x.length) listUsers= x[0];
        return listUsers;
    }

    public String listUsersInOtherClients(String... x) {
        if (0 < x.length) listUsersInOtherClients= x[0];
        return listUsersInOtherClients;
    }

    public String notifyOnNewClientCreate(String... x) {
           if (0 < x.length) notifyOnNewClientCreate= x[0];
           return notifyOnNewClientCreate;
       }

    public String voURI(String... x) {
           if (0 < x.length) voURI= x[0];
           return voURI;
       }

    public String allowQDL(String... x) {
           if (0 < x.length) allowQDL= x[0];
           return allowQDL;
       }

    public String config(String... x) {
           if (0 < x.length) config= x[0];
           return config;
       }

    public String maxClients(String... x) {
           if (0 < x.length) maxClients= x[0];
           return maxClients;
       }

    public String issuer(String... x) {
           if (0 < x.length) issuer = x[0];
           return issuer;
       }


    public String vo(String... x) {
           if (0 < x.length) vo = x[0];
           return vo;
       }

    @Override
    public List<String> allKeys() {
        List<String> allKeys =  super.allKeys();
        allKeys.add(config());
        allKeys.add(issuer());
        allKeys.add(maxClients());
        allKeys.add(vo());
        allKeys.add(voURI());
        allKeys.add(allowQDL());
        allKeys.add(notifyOnNewClientCreate());
        allKeys.add(listUsers());
        allKeys.add(listUsersInOtherClients());
        return allKeys;
    }
}
