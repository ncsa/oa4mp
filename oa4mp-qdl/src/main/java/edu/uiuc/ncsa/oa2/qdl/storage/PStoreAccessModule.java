package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.module.Module;
import edu.uiuc.ncsa.qdl.state.State;

import java.net.URI;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  8:48 AM
 */
public class PStoreAccessModule extends StoreAccessModule {
    public PStoreAccessModule() {
    }

    public PStoreAccessModule(URI namespace, String alias) {
        super(namespace, alias);
    }

    @Override
    public Module newInstance(State state) {
        PStoreAccessModule storeAccessModule = new PStoreAccessModule(URI.create("oa2:/qdl/p_store"), "p_store");
        PermissionStoreFacade permissionStoreFacade = new PermissionStoreFacade();
        doIt(storeAccessModule, permissionStoreFacade, state);
        return storeAccessModule;
    }

    @Override
    protected List<QDLFunction> createFList(StoreFacade configuredStoreFacade) {
        List<QDLFunction> functions =
                super.createFList(configuredStoreFacade);
        PermissionStoreFacade permissionStoreFacade = (PermissionStoreFacade) configuredStoreFacade;
        functions.add(permissionStoreFacade.new ClientCount());
        functions.add(permissionStoreFacade.new GetAdmins());
        functions.add(permissionStoreFacade.new GetClients());
        return functions;
    }
}
