package edu.uiuc.ncsa.myproxy.oa4mp.server.admin;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.ThingFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.Subject;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.SubjectAdmin;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.subjects.SubjectClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.Target;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.TargetAttribute;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.TargetClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.targets.TargetPermission;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.*;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.AdminClient;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  2:31 PM
 */
public class ClientManager {

    public ServiceEnvironmentImpl getSE() {
        return serviceEnvironment;
    }

    ServiceEnvironmentImpl serviceEnvironment;
    protected ClientStore getCS(){return getSE().getClientStore();}

    public ClientManager(ServiceEnvironmentImpl serviceEnvironment) {
        this.serviceEnvironment = serviceEnvironment;
    }

    public void execute(JSONObject json) {
        execute(ThingFactory.getSubject(json), ThingFactory.getAction(json), ThingFactory.getTarget(json), json);
    }

    public void execute(Subject s, Action a, Target t, JSONObject arg) {
        throw new NotImplementedException("Sorry, polymorphism is, apparently, broken in Java");
    }

    protected void checkAdminClient(Identifier identifier, String secret){
        AdminClient ac = getSE().getAdminClientStore().get(identifier);
        if(!ac.getSecret().equals(secret)){
            throw new edu.uiuc.ncsa.security.core.exceptions.IllegalAccessException("Client with id \"" + identifier + "\" is invalid.");
        }
    }
    protected void execute(SubjectAdmin s, ActionApprove a, TargetClient t, JSONObject arg) {
        Identifier adminID = ThingFactory.getIdentifier(arg);
        String secret = ThingFactory.getSecret(arg);
        checkAdminClient(adminID, secret);
        Permission p = getSE().getPermissionStore().get(null);
        if (!p.isApprove()) {
            throw new SecurityException("Error: The administrator is not permitted to approve clients.");
        }
     //  getSE().getClientStore().get()
    }

    protected void execute(SubjectAdmin s, ActionExecute a, TargetClient t, JSONObject arg) {
    }

    protected void execute(SubjectAdmin s, ActionGet a, TargetAttribute t, JSONObject arg) {
    }

    protected void execute(SubjectAdmin s, ActionSet a, TargetAttribute t, JSONObject arg) {
    }

    protected void execute(SubjectAdmin s, ActionRemove a, TargetAttribute t, JSONObject arg) {
    }

    protected void execute(SubjectAdmin s, ActionList a, TargetPermission t, JSONObject arg) {
    }

    protected void execute(SubjectAdmin s, ActionRemove a, TargetPermission t, JSONObject arg) {
    }
    protected void execute(SubjectClient s, ActionRemove a, TargetPermission t, JSONObject arg) {
    }

    protected void execute(SubjectClient s, ActionCreate a, TargetPermission t, JSONObject arg) {

    }

    protected void execute(SubjectClient s, ActionCreate a, TargetClient t, JSONObject arg) {
    }

    protected void execute(SubjectClient s, ActionRemove a, TargetClient t, JSONObject arg) {
    }

    protected void execute(SubjectClient s, ActionSet a, TargetAttribute t, JSONObject arg) {
    }

    protected void execute(SubjectClient s, ActionGet a, TargetAttribute t, JSONObject arg) {
    }

    protected void execute(SubjectClient s, ActionRemove a, TargetAttribute t, JSONObject arg) {
    }


}
