package edu.uiuc.ncsa.oauth2.test;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.RequestFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.TestUtils;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionAdd;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.ActionRemove;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;

import java.util.LinkedList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  1:04 PM
 */
public class PermissionServerTest extends DDServerTests {
    @Override
    public void testAll(CMTestStoreProvider tp2) throws Exception {
        testGetAdmins(tp2);
        testGetClients(tp2);
        addClient(tp2);
        removeClient(tp2);
    }

    public void testMemoryStore() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getMemoryStoreProvider());
    }

    public void testFilestore() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getFsStoreProvider());
    }

    public void testMysql() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getMySQLStoreProvider());
    }

    public void testPostgres() throws Exception {
        testAll((CMTestStoreProvider) TestUtils.getPgStoreProvider());
    }

    public void testGetAdmins(CMTestStoreProvider tp2) throws Exception {
        int clientCount = 4;
        CC cc = setupClients(tp2);
        List<AdminClient> admins = new LinkedList<>();
        for (int i = 0; i < clientCount; i++) {
            AdminClient ac2 = getAdminClient(tp2.getAdminClientStore());
            Permission p = tp2.getPermissionStore().create();
            p.setDelete(true);
            p.setRead(true);
            p.setApprove(true);
            p.setCreate(true);
            p.setWrite(true);
            p.setAdminID(ac2.getIdentifier());
            p.setClientID(cc.client.getIdentifier());
            tp2.getPermissionStore().save(p);
            admins.add(ac2);
        }
        admins.add(cc.adminClient);
        // need this list of identifiers later for checking that the returned result is correct.
        List<Identifier> adminIDs = new LinkedList<>();
        for (AdminClient ac : admins) {
            adminIDs.add(ac.getIdentifier());
        }
        PermissionServer permissionServer = new PermissionServer(tp2.getCOSE());
        //ListAdminsRequest req = new ListAdminsRequest(cc.adminClient, cc.client);
        ListAdminsRequest req = (ListAdminsRequest) RequestFactory.createRequest(null, new TypePermission(), new ActionList(), cc.client, null);
        ListAdminsResponse resp = (ListAdminsResponse) permissionServer.process(req);
        // so add a bunch of admins for a single client and check that they all come back.

        List<AdminClient> returnedACs = resp.getAdmins();
        assert returnedACs.size() == admins.size();
        for (AdminClient x : returnedACs) {
            assert adminIDs.contains(x.getIdentifier());
        }


    }

    public void testGetClients(CMTestStoreProvider tp2) throws Exception {
        int clientCount = 4;
        CC cc = setupClients(tp2);
        List<OA2Client> clients = new LinkedList<>();
        for (int i = 0; i < clientCount; i++) {
            OA2Client client2 = getOa2Client(tp2.getClientStore());
            Permission p = tp2.getPermissionStore().create();
            p.setDelete(true);
            p.setRead(true);
            p.setApprove(true);
            p.setCreate(true);
            p.setWrite(true);
            p.setAdminID(cc.adminClient.getIdentifier());
            p.setClientID(client2.getIdentifier());
            tp2.getPermissionStore().save(p);
            clients.add(client2);
        }
        clients.add(cc.client);
        // need this list of identifiers later for checking that the returned result is correct.
        List<Identifier> clientIDs = new LinkedList<>();
        for (OA2Client ac : clients) {
            clientIDs.add(ac.getIdentifier());
        }
        PermissionServer permissionServer = new PermissionServer(tp2.getCOSE());
        ListClientsRequest req = (ListClientsRequest) RequestFactory.createRequest(cc.adminClient, new TypePermission(), new ActionList(), null, null);
        ListClientResponse resp = (ListClientResponse) permissionServer.process(req);
        // so add a bunch of admins for a single client and check that they all come back.

        List<OA2Client> returnedACs = resp.getClients();
        assert returnedACs.size() == clients.size();
        for (OA2Client x : returnedACs) {
            assert clientIDs.contains(x.getIdentifier());
        }
    }

    /**
     * Adds a client to the permissions of an admin.
     *
     * @param tp2
     * @throws Exception
     */
    public void addClient(CMTestStoreProvider tp2) throws Exception {
        AdminClient adminClient = getAdminClient(tp2.getAdminClientStore());
        OA2Client client = getOa2Client(tp2.getClientStore());
        PermissionServer permissionServer = new PermissionServer(tp2.getCOSE());
        AddClientRequest req = RequestFactory.createRequest(adminClient, new TypePermission(), new ActionAdd(), client, null);
        //AddClientRequest req = new AddClientRequest(adminClient, client);
        AddClientResponse response = (AddClientResponse) permissionServer.process(req);
        PermissionList permissionList = tp2.getPermissionStore().get(adminClient.getIdentifier(), client.getIdentifier());
        try {
            permissionList.canApprove();
            permissionList.canCreate();
            permissionList.canDelete();
            permissionList.canRead();
            permissionList.canWrite();
        } catch (Throwable t) {
            assert false : "failed to have correct permissions";
        }
    }

    public void removeClient(CMTestStoreProvider tp2) throws Exception{
        CC cc = setupClients(tp2);
        RemoveClientRequest req = RequestFactory.createRequest(cc.adminClient, new TypePermission(), new ActionRemove(), cc.client, null);
        PermissionServer permissionServer = new PermissionServer(tp2.getCOSE());
        PermissionResponse resp = (PermissionResponse) permissionServer.process(req);
        assert tp2.getPermissionStore().get(cc.adminClient.getIdentifier(), cc.client.getIdentifier()).isEmpty();

    }
}
