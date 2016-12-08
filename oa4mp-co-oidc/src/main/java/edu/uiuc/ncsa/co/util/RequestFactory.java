package edu.uiuc.ncsa.co.util;

import edu.uiuc.ncsa.co.util.attributes.AttributeGetRequest;
import edu.uiuc.ncsa.co.util.attributes.AttributeRemoveRequest;
import edu.uiuc.ncsa.co.util.attributes.AttributeSetRequest;
import edu.uiuc.ncsa.co.util.client.*;
import edu.uiuc.ncsa.co.util.permissions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SAT;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.actions.*;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.Type;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeAttribute;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypeClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types.TypePermission;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Client;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.lang.reflect.Constructor;
import java.lang.reflect.Parameter;
import java.util.Arrays;

/**
 * This creates the correct request based on the parameters.
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  5:00 PM
 */
public class RequestFactory implements SAT {
    public static AbstractDDRequest convertToRequest(JSONObject json) {
        AbstractDDRequest req = null;
        BaseClient client = SATFactory.getSubject(json);
        Action action = SATFactory.getMethod(json);
        if (action instanceof MissingAction) {
            throw new GeneralException("Error: no valid method found");
        }
        Type type = SATFactory.getType(json);
        BaseClient target = SATFactory.getTarget(json);
        switch (SATFactory.getSubjectValue(json)) {
            case SUBJECT_ADMIN_VALUE:
                //  return createSubjectAdminRequest(json);
            case SUBJECT_CLIENT_VALUE:
                break;
            case SUBJECT_UNKNOWN_VALUE:
            default:
                throw new GeneralException("Unknown subject type");
        }

        return req;
    }

    public static class RequestObject {
        public AdminClient adminClient;
        public OA2Client client;
        public Type type;
        public Action action;
        public JSON content;
    }

    public static AbstractDDRequest createRequest(RequestObject ro){
        return createRequest((AdminClient)ro.adminClient,
                ro.type,
                ro.action,
                (OA2Client)ro.client,
                ro.content);
    }

    public Parameter[] convertObjectsToParameters(Object[] objArray) {
        Parameter[] paramArray = new Parameter[objArray.length];
        int i = 0;
        for (Object obj : objArray) {
            try {
                Constructor<Parameter> cons = Parameter.class.getConstructor(obj.getClass());
                paramArray[i++] = cons.newInstance(obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("This method can't handle objects of type: " + obj.getClass(), e);
            }
        }
        return paramArray;
    }
    public static AbstractDDRequest createRequest(BaseClient b, Type t, Action a, BaseClient c, JSON x ){
        throw new NFWException("Error: If this is invoked, it is because Java is not resolving its overloaded classes right.");
    }

    /* ***** Attribute requests */
    public static AttributeGetRequest createRequest(AdminClient aSubj,
                                                    TypeAttribute typeAttribute,
                                                    ActionGet actionGet,
                                                    OA2Client cTarget,
                                                    JSON content) {
        //JSON content = SATFactory.getContent(json);
        if (!content.isArray()) {
            throw new GeneralException("Content must be a list of attributes to get");
        }
        JSONArray array = (JSONArray) content;
        String[] arrayString = (String[]) array.toArray(new String[array.size()]);
        return new AttributeGetRequest(aSubj, cTarget, Arrays.asList(arrayString));
    }

    public static AttributeSetRequest createRequest(AdminClient aSubj,
                                                    TypeAttribute typeAttribute,
                                                    ActionSet actionSet,
                                                    OA2Client cTarget,
                                                    JSON content) {
        if (content.isArray()) {
            throw new GeneralException("Content must be a map of attributes to set");
        }
        return new AttributeSetRequest(aSubj, cTarget, (JSONObject) content);
    }

    public static AttributeRemoveRequest createRequest(AdminClient aSubj,
                                                       TypeAttribute typeAttribute,
                                                       ActionRemove actionRemove,
                                                       OA2Client cTarget,
                                                       JSON content) {
        //JSON content = SATFactory.getContent(json);
        if (!content.isArray()) {
            throw new GeneralException("Content must be a list of attributes to get");
        }
        JSONArray array = (JSONArray) content;
        String[] arrayString = (String[]) array.toArray(new String[array.size()]);
        return new AttributeRemoveRequest(aSubj, cTarget, Arrays.asList(arrayString));
    }

    /* ***** Permission requests */


    public static AddClientRequest createRequest(AdminClient adminClient, TypePermission typeP, ActionAdd acreate, OA2Client client, JSON json) {
        return new AddClientRequest(adminClient, client);
    }

    public static RemoveClientRequest createRequest(AdminClient adminClient, TypePermission typeP, ActionRemove actionRemove, OA2Client client, JSON json) {
        return new RemoveClientRequest(adminClient, client);
    }

    public static PermissionRequest createRequest(AdminClient adminClient, TypePermission typeP, ActionList aList, OA2Client client, JSON json) {
        if (client == null) {
            return new ListClientsRequest(adminClient, client);
        }
        if (adminClient == null) {
            return new ListAdminsRequest(adminClient, client);
        }
        throw new GeneralException("inconsistent arguments for list request");
    }

    /* ***** Client requests */
    public static ApproveRequest createRequest(AdminClient adminClient, TypeClient typeClient, ActionApprove actionApprove, OA2Client client, JSON json) {
        return new ApproveRequest(adminClient, client);
    }


    public static UnapproveRequest createRequest(AdminClient adminClient, TypeClient typeClient, ActionUnapprove actionUnapprove,
                                                 OA2Client client, JSON json) {
        return new UnapproveRequest(adminClient, client);
    }

    public static CreateRequest createRequest(AdminClient adminClient, TypeClient typeClient, ActionCreate actionCreate,
                                              OA2Client client, JSON json) {
        if (json.isArray()) {
            throw new IllegalArgumentException("Error: cannot create a client from a JSON array -- it must be an map (JSON object) of key/value pairs");
        }
        return new CreateRequest(adminClient, client, (JSONObject) json);
    }


    public static RemoveRequest createRequest(AdminClient adminClient, TypeClient typeClient, ActionRemove actionRemove,
                                              OA2Client client, JSON json) {
        return new RemoveRequest(adminClient, client);
    }

    public static GetRequest createRequest(AdminClient adminClient,
                                           TypeClient typeClient,
                                           ActionGet actionGet,
                                           OA2Client client,
                                           JSON json){
        return new GetRequest(adminClient, client);
    }
}
