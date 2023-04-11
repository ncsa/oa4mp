package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionException;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.DoubleDispatchServer;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Request;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Server;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  3:19 PM
 */
public abstract class AbstractDDServer implements DoubleDispatchServer, Server {
    public AbstractDDServer(OA2SE cose) {
        this.cose = cose;
    }

    protected OA2SE cose;


    @Override
    public Response process(Request request) {
        return request.process(this);
    }

    /**
     * This will take a client and a list of attributes and return the requested subset.
     *
     * @param client
     * @param attributes
     * @return
     */
    protected OA2Client subset(OA2Client client, List<String> attributes) {
        ColumnMap map = new ColumnMap();

        cose.getClientStore().getXMLConverter().toMap(client, map);
        ColumnMap reducedMap = new ColumnMap();

        for (String key : attributes) {
            reducedMap.put(key, map.get(key));
        }
        // Have to always include the identifier.
        reducedMap.put(cose.getClientStore().getMapConverter().getKeys().identifier(), client.getIdentifierString());
        OA2Client x = (OA2Client) cose.getClientStore().getMapConverter().fromMap(reducedMap, null);
        return x;

    }

    protected AdminClient subset(AdminClient client, List<String> attributes) {
        ColumnMap map = new ColumnMap();

        cose.getAdminClientStore().getMapConverter().toMap(client, map);
        ColumnMap reducedMap = new ColumnMap();

        for (String key : attributes) {
            reducedMap.put(key, map.get(key));
        }
        // Have to always include the identifier.
        reducedMap.put(cose.getClientStore().getMapConverter().getKeys().identifier(), client.getIdentifierString());
        AdminClient x = (AdminClient) cose.getAdminClientStore().getMapConverter().fromMap(reducedMap, null);
        return x;

    }

    protected void canRead(AbstractDDRequest request) {
        if (request.getAdminClient() != null) {
            isACApproved(request);
            getPermissions(request).canRead();
        }
        if (request.getClient() == null) throw new PermissionException("Missing client.");
    }

    protected void canWrite(AbstractDDRequest request) {
        // the contract is that if the subject is an admin, check the permissions.
        if (request.getAdminClient() != null) {
            isACApproved(request);
            getPermissions(request).canWrite();
        }
        // if the subject is a client, then the object must be absent or the same
        if (request.getClient() == null) throw new PermissionException("Missing client.");

    }

    protected void isACApproved(AbstractDDRequest request) {
        if (!getClientApprovalStore().isApproved(request.adminClient.getIdentifier())) {
            throw new UnapprovedClientException("This admin client is not approved", request.adminClient);
        }
    }

    protected void canApprove(AbstractDDRequest request) {
        if (request.getAdminClient() != null) {

            isACApproved(request);
            getPermissions(request).canApprove();
        }
        if (request.getClient() == null) throw new PermissionException("Missing client.");

    }

    protected void canDelete(AbstractDDRequest request) {
        if (request.getAdminClient() != null) {

            isACApproved(request);
            getPermissions(request).canDelete();
        }
        if (request.getClient() == null) throw new PermissionException("Missing client.");

    }

    protected void canCreate(AbstractDDRequest request) {
        isACApproved(request);
        getPermissions(request).canCreate();
    }

    protected PermissionList getPermissions(AbstractDDRequest request) {
        return cose.getPermissionStore().get(request.adminClient.getIdentifier(), request.client.getIdentifier());
    }

    protected ClientStore getClientStore() {
        return cose.getClientStore();
    }

    protected ClientApprovalStore getClientApprovalStore() {
        return cose.getClientApprovalStore();
    }

    protected PermissionsStore<Permission> getPermissionStore() {
        return cose.getPermissionStore();
    }

    protected AdminClientStore<AdminClient> getAdminClientStore() {
        return cose.getAdminClientStore();
    }
}
