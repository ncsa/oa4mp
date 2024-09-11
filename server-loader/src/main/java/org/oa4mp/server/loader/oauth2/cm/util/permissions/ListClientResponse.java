package org.oa4mp.server.loader.oauth2.cm.util.permissions;


import org.oa4mp.server.loader.oauth2.storage.clients.OA2Client;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  11:28 AM
 */
public class ListClientResponse extends PermissionResponse{
    List<OA2Client> clients;

    public ListClientResponse(List<OA2Client> clients) {
        this.clients = clients;
    }

    public List<OA2Client> getClients() {
        return clients;
    }
}
