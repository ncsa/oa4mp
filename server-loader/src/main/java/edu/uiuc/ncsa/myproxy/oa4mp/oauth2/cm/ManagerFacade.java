package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.admin.AdminClientServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.attributes.AttributeServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.client.ClientServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.PermissionServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeAdmin;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeAttribute;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.services.Response;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.BaseClient;
import net.sf.json.JSONObject;
import org.apache.commons.codec.digest.DigestUtils;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.RequestFactory.createRequest;
import static edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  2:31 PM
 */
public class ManagerFacade {

    public OA2SE getSE() {
        return serviceEnvironment;
    }

    OA2SE serviceEnvironment;


    public ManagerFacade(OA2SE serviceEnvironment) {
        this.serviceEnvironment = serviceEnvironment;
    }


    ClientServer clientServer;
    AdminClientServer adminClientServer;
    PermissionServer permissionServer;
    AttributeServer attributeServer;

    public AttributeServer getAttributeServer() {
        if (attributeServer == null) {
            attributeServer = new AttributeServer(getSE());
        }
        return attributeServer;
    }

    public ClientServer getClientServer() {
        if (clientServer == null) {
            clientServer = new ClientServer(getSE());
        }
        return clientServer;
    }

    public AdminClientServer getAdminClientServer() {
        if (adminClientServer == null) {
            adminClientServer = new AdminClientServer(getSE());
        }
        return adminClientServer;
    }

    public PermissionServer getPermissionServer() {
        if (permissionServer == null) {
            permissionServer = new PermissionServer(getSE());
        }
        return permissionServer;
    }

    protected Response process(AdminClient adminClient, JSONObject rawJSON) {
        checkAdminClientSecret(adminClient);
        // CIL-698 fix:
        // Up to this point, the admin client is just an id + the secret that was passed in
        // So we could check the credentials. If it gets to here, it is valid.
        // Since the passed in adminClient is otherwise empty, we now we replace it with the real one:
        adminClient = getSE().getAdminClientStore().get(adminClient.getIdentifier());
        switch (getTargetValue(rawJSON)) {
            case TARGET_ADMIN_VALUE:
                return process(adminClient, (AdminClient) getTarget(rawJSON), rawJSON);
            case TARGET_CLIENT_VALUE:
                return process(adminClient, (OA2Client) getTarget(rawJSON), rawJSON);
            case TARGET_NO_VALUE:
                return process(adminClient, (OA2Client) null, rawJSON);
        }
        throw new NotImplementedException("unrecognized target of action");
    }

    /**
     * ***************************
     */
      /*                             *
      /*        KEEP THIS            *
      /*                             *
      /*******************************/
    protected void checkOA2ClientSecret(OA2Client client) {
        checkClientSecret(client, getSE().getClientStore());
    }

    protected void checkAdminClientSecret(AdminClient client) {
        checkClientSecret(client, getSE().getAdminClientStore());

    }

    /**
     * This takes the client created from the JSON that came in the request and goes
     * to the correct store, grabs the client with that ID stashed there and then checks that
     * the secrets match. This means that the argument's secret is the actual secret and the
     * stored client's secret is a hash of it.
     *
     * @param client
     * @param store
     */
    protected void checkClientSecret(BaseClient client, BaseClientStore store) {
        if (client == null) {
            throw new GeneralException("Error: No client found.");
        }
        String rawSecret = client.getSecret();
        if (rawSecret == null || rawSecret.length() == 0) {
            DebugUtil.trace(this, "doIt: no secret, throwing exception.");
            throw new GeneralException("Missing secret");
        }


        if (client.getSecret() == null || client.getSecret().isEmpty()) {
            throw new GeneralException("Error: No secret given for this client.");

        }

        if (!store.containsKey(client.getIdentifier())) {
            throw new GeneralException("Error: No such client for identifier \"" + client.getIdentifierString() + "\".");
        }
        BaseClient storedClient = (BaseClient) store.get(client.getIdentifier());


        if (!storedClient.getSecret().equals(DigestUtils.sha1Hex(rawSecret))) {
            DebugUtil.trace(this, "doIt: bad secret, throwing exception.");
            throw new GeneralException("Incorrect secret. Unauthorized client.");
        }
    }

    protected Response process(OA2Client oa2Client, JSONObject rawJSON) {
   /*     if(getMethodValue(rawJSON) == ACTION_CREATE_VALUE && getTargetValue(rawJSON) == TARGET_NO_VALUE){
            // We will allow an anonymous client create request -- this is identical to using the web form
            // All other client operations are forbidden.
            return process((AdminClient) null, oa2Client, new ActionCreate(), rawJSON);
        }*/
        
        throw new edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException("Error: access for standard clients is not allowed");
        // Fix for CIL-460.
        // note that what follows works perfectly well, but allows standard clients full access to the management API
        // which gives them the ability to change their scopes and other types of access.
        // At this point we have decided that is a security risk.

        /*******************************/
        /*                             *
        /*        KEEP THIS            *
        /*                             *
        /*******************************/

     /*   checkOA2ClientSecret(oa2Client.getSecret(),
                (OA2Client) getSE().getClientStore().get(oa2Client.getIdentifier()),
                getSE().getClientStore());

      /*  switch (getTargetValue(rawJSON)) {
            case TARGET_ADMIN_VALUE:
                return process(oa2Client, (AdminClient) getTarget(rawJSON), rawJSON);

            case TARGET_CLIENT_VALUE:
                return process(oa2Client, (OA2Client) getTarget(rawJSON), rawJSON);
            case TARGET_NO_VALUE:
                return process(oa2Client, (AdminClient) null, rawJSON);

        }
        throw new NotImplementedException("unrecognized target of action");
*/
    }

    protected Response process(OA2Client subject, OA2Client target, JSONObject rawJSON) {

        throw new NotImplementedException("unrecognized target of action");
    }

    protected Response process(AdminClient subject, AdminClient target, JSONObject rawJSON) {
        throw new NotImplementedException("unrecognized target of action");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionAdd actionAdd, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_PERMISSION_VALUE) {
            return getPermissionServer().process(createRequest(subject,
                    new TypePermission(),
                    actionAdd, target,
                    SATFactory.getContent(rawJSON)
            ));

        }

        throw new IllegalArgumentException("Unknown type.");
    }

    protected Response process(AdminClient subject, OA2Client target, ActionApprove actionApprove, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_CLIENT_VALUE) {
            return getClientServer().process(createRequest(subject, new TypeClient(), actionApprove, target,
                    SATFactory.getContent(rawJSON)));
        }
        throw new IllegalArgumentException("Unknown type.");
    }

    protected Response process(AdminClient subject, OA2Client target, ActionCreate actionCreate, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_CLIENT_VALUE) {
            return getClientServer().process(createRequest(subject,
                    new TypeClient(),
                    actionCreate,
                    target,
                    SATFactory.getContent(rawJSON))
            );

        }

        throw new IllegalArgumentException("Unknown type.");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionExecute actionExecute, JSONObject rawJSON) {
        throw new IllegalArgumentException("Unknown type.");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionGet actionGet, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_ATTRIBUTE_VALUE) {
            return getAttributeServer().process(createRequest(subject, new TypeAttribute(), actionGet, target,
                    SATFactory.getContent(rawJSON)));
        }

        if (getTypeValue(rawJSON) == TYPE_CLIENT_VALUE) {
            return getClientServer().process(createRequest(subject, new TypeClient(), actionGet, target,
                    SATFactory.getContent(rawJSON)));
        }

        if (getTypeValue(rawJSON) == TYPE_ADMIN_VALUE) {
            return getAdminClientServer().process(createRequest(subject, new TypeAdmin(), actionGet, target,
                    SATFactory.getContent(rawJSON)));
        }
        if (getTypeValue(rawJSON) == TYPE_PERMISSION_VALUE) {
            return getPermissionServer().process(createRequest(subject, new TypeClient(), actionGet, target,
                    SATFactory.getContent(rawJSON)));
        }
        throw new IllegalArgumentException("Unknown type.");
    }

    protected Response process(AdminClient subject, OA2Client target, ActionList actionList, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_PERMISSION_VALUE) {
            return getPermissionServer().process(createRequest(subject, new TypePermission(), actionList, target,
                    SATFactory.getContent(rawJSON)));
        }

        throw new IllegalArgumentException("Unknown type.");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionSet actionSet, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_ATTRIBUTE_VALUE) {
            return getAttributeServer().process(createRequest(subject, new TypeAttribute(), actionSet, target,
                    SATFactory.getContent(rawJSON)));
        }
        throw new IllegalArgumentException("Unknown type.");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionRemove actionRemove, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_ATTRIBUTE_VALUE) {
            return getAttributeServer().process(createRequest(subject, new TypeAttribute(), actionRemove, target,
                    SATFactory.getContent(rawJSON)));
        }
        if (getTypeValue(rawJSON) == TYPE_CLIENT_VALUE) {
            return getClientServer().process(createRequest(subject, new TypeClient(), actionRemove, target,
                    SATFactory.getContent(rawJSON)));
        }
        if (getTypeValue(rawJSON) == TYPE_PERMISSION_VALUE) {
            return getPermissionServer().process(createRequest(subject, new TypePermission(), actionRemove, target,
                    SATFactory.getContent(rawJSON)));
        }

        throw new IllegalArgumentException("Unknown type.");

    }

    protected Response process(AdminClient subject, OA2Client target, ActionUnapprove actionUnapprove, JSONObject rawJSON) {
        if (getTypeValue(rawJSON) == TYPE_CLIENT_VALUE) {
            return getClientServer().process(createRequest(subject, new TypeClient(), actionUnapprove, target,
                    SATFactory.getContent(rawJSON)));
        }
        throw new IllegalArgumentException("Unknown type.");

    }


    protected Response process(OA2Client subject, AdminClient target, JSONObject rawJSON) {

        switch (getMethodValue(rawJSON)) {
            case ACTION_ADD_VALUE:
                return process(target, subject, new ActionAdd(), rawJSON);
            case ACTION_APPROVE_VALUE:
                return process(target, subject, new ActionApprove(), rawJSON);
            case ACTION_CREATE_VALUE:
                return process(target, subject, new ActionCreate(), rawJSON);
            case ACTION_EXECUTE_VALUE:
                return process(target, subject, new ActionExecute(), rawJSON);
            case ACTION_GET_VALUE:
                return process(target, subject, new ActionGet(), rawJSON);
            case ACTION_LIST_VALUE:
                return process(target, subject, new ActionList(), rawJSON);
            case ACTION_SET_VALUE:
                return process(target, subject, new ActionSet(), rawJSON);
            case ACTION_REMOVE_VALUE:
                return process(target, subject, new ActionRemove(), rawJSON);
            case ACTION_UNAPPROVE_VALUE:

        }
        throw new NotImplementedException("unrecognized target of action");

    }


    protected Response process(AdminClient subject, OA2Client target, JSONObject rawJSON) {
        switch (getMethodValue(rawJSON)) {
            case ACTION_ADD_VALUE:
                return process(subject, target, new ActionAdd(), rawJSON);
            case ACTION_APPROVE_VALUE:
                return process(subject, target, new ActionApprove(), rawJSON);
            case ACTION_CREATE_VALUE:
                return process(subject, target, new ActionCreate(), rawJSON);
            case ACTION_EXECUTE_VALUE:
                return process(subject, target, new ActionExecute(), rawJSON);
            case ACTION_GET_VALUE:
                return process(subject, target, new ActionGet(), rawJSON);
            case ACTION_LIST_VALUE:
                return process(subject, target, new ActionList(), rawJSON);
            case ACTION_SET_VALUE:
                return process(subject, target, new ActionSet(), rawJSON);
            case ACTION_UNAPPROVE_VALUE:
                return process(subject, target, new ActionUnapprove(), rawJSON);
            case ACTION_REMOVE_VALUE:
                return process(subject, target, new ActionRemove(), rawJSON);
        }
        throw new NotImplementedException("unrecognized target of action");

    }


    public Response process(JSONObject rawJSON) {
        switch (getSubjectValue(rawJSON)) {
            case SUBJECT_ADMIN_VALUE:
                return process((AdminClient) getSubject(rawJSON), rawJSON);
            case SUBJECT_CLIENT_VALUE:
                return process((OA2Client) getSubject(rawJSON), rawJSON);
            case SUBJECT_UNKNOWN_VALUE:
                return process((OA2Client) null, rawJSON);
        }
        throw new IllegalArgumentException("Unknown type.");

    }
}
