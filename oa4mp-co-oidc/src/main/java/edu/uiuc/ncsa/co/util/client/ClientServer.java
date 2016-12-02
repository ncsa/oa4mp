package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.co.util.AbstractDDServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:55 PM
 */
public class ClientServer extends AbstractDDServer {
    public ClientServer(COSE cose) {
        super(cose);
    }


    public ClientResponse approve(ApproveRequest request){
        canApprove(request);
        Identifier id = request.getClient().getIdentifier();
        ClientApproval approval = null;
        if(getClientApprovalStore().containsKey(id)){
            approval = (ClientApproval) getClientApprovalStore().get(id);
        }else{
            approval = (ClientApproval) getClientApprovalStore().create();
            // approval ID must be the same as the client's
            approval.setIdentifier(id);
        }
        approval.setApprover(request.getAdminClient().getName());
        approval.setApproved(true);
        getClientApprovalStore().save(approval);
        return new ClientResponse();
    }

    public ClientResponse unapprove(UnapproveRequest request){
          canApprove(request);
          ClientApproval approval = (ClientApproval) getClientApprovalStore().get(request.getClient().getIdentifier());
          approval.setApprover(request.getAdminClient().getName());
          approval.setApproved(false);
          getClientApprovalStore().save(approval);
          return new ClientResponse();
      }

    public CreateResponse create(CreateRequest request){
        //canCreate(request);
        //requires and admin client and hashmap
        ColumnMap values = new ColumnMap();
        values.putAll(request.getAttributes());
        // values.putAll(); // add all the values passed in
        ClientKeys keys = (ClientKeys) getClientStore().getACConverter().getKeys();
        OA2Client client = (OA2Client) getClientStore().create();
        values.put(keys.identifier(), client.getIdentifier());
        values.put(keys.creationTS(), client.getCreationTS());
     //   Identifier clientID = client.getIdentifier();
        getClientStore().getACConverter().fromMap(values, client);
        getClientStore().save(client);
       // client.setIdentifier(clientID); // since this gets scrubbed by the previous method.
        // response requires new client and its actual secret
        return new CreateResponse(client);
    }

    /**
     * remove the client completely and all references to it.
     * @param request
     * @return
     */
    public ClientResponse remove(RemoveRequest request){
        canDelete(request);
        Identifier clientID = request.getClient().getIdentifier();
        getClientApprovalStore().remove(clientID);
        List<Identifier> admins = getPermissionStore().getAdmins(clientID);
        // remove all permissions for this client and these admins
        for(Identifier adminID : admins){
            PermissionList  permissions = getPermissionStore().get(adminID, clientID);
            for(Permission p : permissions){
                getPermissionStore().remove(p.getIdentifier());
            }
        }
        getClientStore().remove(clientID);
        return new ClientResponse();
    }


}
