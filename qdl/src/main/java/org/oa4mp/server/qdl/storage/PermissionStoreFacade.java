package org.oa4mp.server.qdl.storage;

import org.qdl_lang.exceptions.BadArgException;
import org.qdl_lang.extensions.QDLFunction;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import org.qdl_lang.variables.values.QDLValue;

import java.util.ArrayList;
import java.util.List;

import static org.qdl_lang.variables.values.QDLValue.asQDLValue;

/**
 * Adds in a few features specific to permission stores.
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  8:31 AM
 */
public class PermissionStoreFacade extends StoreFacade {


    protected QDLPermissionStoreAccessor getPS() {
        return (QDLPermissionStoreAccessor) getStoreAccessor();
    }

    public static String CLIENT_COUNT_NAME = "client_count";
    public static String CLIENTS_NAME = "get_clients";
    public static String ADMINS_NAME = "get_admins";

    public class ClientCount implements QDLFunction {
        @Override
        public String getName() {
            return CLIENT_COUNT_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            checkInit();

            if (objects.length != 1 || !(objects[0].isString())) {
                throw new BadArgException(getName() + " requires the admin id as its argument",0);
            }
            return asQDLValue(Long.valueOf(getPS().getClientCount(BasicIdentifier.newID(objects[0].asString()))));
        }


        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(admin_id) - return the number of clients associated with this admin id");
            doxx.add("See also: " + CLIENTS_NAME);
            return doxx;
        }
    }

    public class GetClients implements QDLFunction {
        @Override
        public String getName() {
            return CLIENTS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            checkInit();

            if (objects.length != 1 || !(objects[0].isString())) {
                throw new BadArgException(getName() + " requires the admin id as its argument",0);
            }
            List<Identifier> ids = getPS().getClients(BasicIdentifier.newID(objects[0].asString()));

            QDLStem stem = new QDLStem();
            for (Identifier id : ids) {
                stem.listAdd(asQDLValue(id.toString()));
            }
            return asQDLValue(stem);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(admin_id) - return a list of clients associated with this admin id");
            doxx.add("See also: " + CLIENT_COUNT_NAME + ", " + ADMINS_NAME);
            return doxx;
        }
    }

    public class GetAdmins implements QDLFunction {
        @Override
        public String getName() {
            return ADMINS_NAME;
        }

        @Override
        public int[] getArgCount() {
            return new int[]{1};
        }

        @Override
        public QDLValue evaluate(QDLValue[] objects, State state) {
            checkInit();

            if (objects.length != 1 || !(objects[0].isString())) {
                throw new BadArgException(getName() + " requires the client id as its argument",0);
            }
            List<Identifier> ids = getPS().getAdmins(BasicIdentifier.newID(objects[0].asString()));

            QDLStem stem = new QDLStem();
            for (Identifier id : ids) {
                stem.listAdd(asQDLValue(id.toString()));
            }
            return asQDLValue(stem);
        }

        @Override
        public List<String> getDocumentation(int argCount) {
            List<String> doxx = new ArrayList<>();
            doxx.add(getName() + "(client_id) - return a list of admins associated with this client id");
            doxx.add("See also: " + CLIENTS_NAME);
            return doxx;
        }
    }

    @Override
    protected QDLStoreAccessor createAccessor(String storeType) throws Exception {
        QDLStoreAccessor a = null;

        a = super.createAccessor(storeType);
        if (a != null) {
            return a;
        }
        switch (storeType) {
            case STORE_TYPE_PERMISSION_STORE:
                a = new QDLPermissionStoreAccessor(storeType, getEnvironment().getPermissionStore(), getEnvironment().getMyLogger());
                a.setMapConverter(new PermissionStemMC(getEnvironment().getPermissionStore().getMapConverter()));
                break;
        }
        return a;
    }
}
