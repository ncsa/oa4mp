package edu.uiuc.ncsa.co.util.client;

import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.co.util.AbstractDDServer;
import edu.uiuc.ncsa.co.util.RequestFactory;
import edu.uiuc.ncsa.co.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionAdd;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.ClientKeys;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

import java.security.SecureRandom;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/28/16 at  1:55 PM
 */
public class ClientServer extends AbstractDDServer {
    public ClientServer(COSE cose) {
        super(cose);
    }


    public ClientResponse approve(ApproveRequest request) {
        canApprove(request);
        Identifier id = request.getClient().getIdentifier();
        ClientApproval approval = null;
        if (getClientApprovalStore().containsKey(id)) {
            approval = (ClientApproval) getClientApprovalStore().get(id);
        } else {
            approval = (ClientApproval) getClientApprovalStore().create();
            // approval ID must be the same as the client's
            approval.setIdentifier(id);
        }
        approval.setApprover(request.getAdminClient().getName());
        approval.setApproved(true);
        getClientApprovalStore().save(approval);
        return new ClientResponse();
    }

    public ClientResponse unapprove(UnapproveRequest request) {
        canApprove(request);
        ClientApproval approval = (ClientApproval) getClientApprovalStore().get(request.getClient().getIdentifier());
        approval.setApprover(request.getAdminClient().getName());
        approval.setApproved(false);
        getClientApprovalStore().save(approval);
        return new ClientResponse();
    }

    SecureRandom random = new SecureRandom();

    public CreateResponse create(CreateRequest request) {
        //canCreate(request);
        //requires and admin client and hashmap
        ColumnMap values = new ColumnMap();
        values.putAll(request.getAttributes());
        // values.putAll(); // add all the values passed in
        ClientKeys keys = (ClientKeys) getClientStore().getACConverter().getKeys();
        OA2Client client = (OA2Client) getClientStore().create();
        values.put(keys.identifier(), client.getIdentifier());
        values.put(keys.creationTS(), client.getCreationTS());
        String secret = null;
        if (values.containsKey(keys.secret())) {
            // if the secret is supplied, just store its hash
            secret = (String) values.get(keys.secret());
        } else {
            // no secret means to create one.
            byte[] bytes = new byte[cose.getClientSecretLength()];
            random.nextBytes(bytes);
            secret = Base64.encodeBase64URLSafeString(bytes);
        }
        String hash = DigestUtils.sha1Hex(secret);
        values.put(keys.secret(), hash);

        getClientStore().getACConverter().fromMap(values, client);
        getClientStore().save(client);
        // client.setIdentifier(clientID); // since this gets scrubbed by the previous method.
        // response requires new client and its actual secret
        // set the permissions for this.
        PermissionServer permissionServer = new PermissionServer(cose);
        permissionServer.process(RequestFactory.createRequest(request.getAdminClient(), new TypePermission(), new ActionAdd(), client, null));

        return new CreateResponse(client, secret);
    }

    /**
     * remove the client completely and all references to it.
     *
     * @param request
     * @return
     */
    public ClientResponse remove(RemoveRequest request) {
        canDelete(request);
        Identifier clientID = request.getClient().getIdentifier();
        getClientApprovalStore().remove(clientID);
        List<Identifier> admins = getPermissionStore().getAdmins(clientID);
        // remove all permissions for this client and these admins
        for (Identifier adminID : admins) {
            PermissionList permissions = getPermissionStore().get(adminID, clientID);
            for (Permission p : permissions) {
                getPermissionStore().remove(p.getIdentifier());
            }
        }
        getClientStore().remove(clientID);
        return new ClientResponse();
    }

    public ClientResponse get(GetRequest request) {
        canRead(request);
        OA2Client client = (OA2Client) getClientStore().get(request.getClient().getIdentifier());
        client.setSecret(""); // do not return the secret or its hash
        cose.getClientApprovalStore().isApproved(client.getIdentifier());
        return new GetResponse(client,cose.getClientApprovalStore().isApproved(client.getIdentifier()));
    }

}
