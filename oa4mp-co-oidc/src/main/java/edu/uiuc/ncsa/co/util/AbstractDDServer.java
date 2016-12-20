package edu.uiuc.ncsa.co.util;

import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.services.DoubleDispatchServer;
import edu.uiuc.ncsa.security.delegation.services.Request;
import edu.uiuc.ncsa.security.delegation.services.Response;
import edu.uiuc.ncsa.security.delegation.services.Server;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/30/16 at  3:19 PM
 */
public abstract class AbstractDDServer implements DoubleDispatchServer, Server {
    public AbstractDDServer(COSE cose) {
        this.cose = cose;
    }

    protected COSE cose;


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

        cose.getClientStore().getACConverter().toMap(client, map);
        ColumnMap reducedMap = new ColumnMap();

        for (String key : attributes) {
            reducedMap.put(key, map.get(key));
        }
        // Have to always include the identifier.
        reducedMap.put(cose.getClientStore().getACConverter().getKeys().identifier(), client.getIdentifierString());
        OA2Client x = (OA2Client) cose.getClientStore().getACConverter().fromMap(reducedMap, null);
        return x;

    }

    protected void canRead(AbstractDDRequest request) {
        isACApproved(request);
        getPermissions(request).canRead();
    }

    protected void canWrite(AbstractDDRequest request) {
        isACApproved(request);

        getPermissions(request).canWrite();
    }
   protected void isACApproved(AbstractDDRequest request){
      if(!getClientApprovalStore().isApproved(request.adminClient.getIdentifier())){
          throw new UnapprovedClientException("This client is not approved", request.adminClient);
      }
   }
    protected void canApprove(AbstractDDRequest request) {

        isACApproved(request);
        getPermissions(request).canApprove();
    }

    protected void canDelete(AbstractDDRequest request) {
        isACApproved(request);
        getPermissions(request).canDelete();
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
