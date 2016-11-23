package edu.uiuc.ncsa.co;

import edu.uiuc.ncsa.co.ldap.LDAPStore;
import edu.uiuc.ncsa.co.loader.COSE;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.Action;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionApprove;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionCreate;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionRemove;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.Subject;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.Target;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.Type;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeClient;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import net.sf.json.JSONObject;

import java.util.Date;

/**
 * Since there are tons of possible subject-action-target combinations, the idea here is to
 * let polymorphism do all the work rather than some gnarly set of switch statements.
 * This does require a bit of work creating these {@link edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.Thing}s,
 * but is much simpler to maintain.
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  2:31 PM
 */
public class ClientManager {

    public COSE getSE() {
        return serviceEnvironment;
    }

    COSE serviceEnvironment;

    protected ClientStore getCS() {
        return getSE().getClientStore();
    }

    public ClientManager(COSE serviceEnvironment) {
        this.serviceEnvironment = serviceEnvironment;
    }

    public void execute(JSONObject json) {
        //  getSE().getClientStore().g
        //execute(SATFactory.getSubject(json), SATFactory.getMethod(json), SATFactory.getTarget(json), json);
    }

    protected PermissionsStore getPermissionStore() {
        return getSE().getPermissionStore();
    }

    protected ClientStore getClientStore() {
        return getSE().getClientStore();
    }

    protected ClientApprovalStore getClientApprovalStore() {
        return getSE().getClientApprovalStore();
    }

    protected AdminClientStore getAdminClientStore() {
        return getSE().getAdminClientStore();
    }

    protected LDAPStore getLDAPStore() {
        return getSE().getLDAPStore();
    }

    public void execute(Subject s, Action a, Type type, Target t, JSONObject arg) {
        throw new NotImplementedException("Sorry, polymorphism is, apparently, broken in Java");
    }

    public void execute(AdminClient adminClient,
                        ActionCreate actionCreate,
                        TypeClient typeClient,
                        Client client) {
    }

    public void execute(AdminClient adminClient,
                        ActionApprove actionCreate,
                        TypeClient typeClient,
                        Client client) {
        PermissionList permissions =getPermissionStore().get(adminClient.getIdentifier(), client.getIdentifier());
        permissions.canApprove();
        ClientApproval ca = null;
        if (getSE().getClientApprovalStore().containsKey(client.getIdentifier())) {
            ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        } else {
            ca = (ClientApproval) getClientApprovalStore().create();
        }
        ca.setApproved(true);
        ca.setApprover(adminClient.getName());
        ca.setApprovalTimestamp(new Date());
        getClientApprovalStore().save(ca);
    }

    public void execute(AdminClient adminClient,
                        ActionRemove actionRemove,
                        TypeClient typeClient,
                        Client client) {
        PermissionList permissions = getPermissionStore().get(adminClient.getIdentifier(), client.getIdentifier());
        permissions.canDelete();
        getClientStore().remove(client.getIdentifier());
        PermissionList permisions =  getPermissionStore().get(adminClient.getIdentifier(), client.getIdentifier());
    }
}
