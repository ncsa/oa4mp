package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;

import java.io.IOException;
import java.sql.SQLException;

/**
 * This servlet loads the environment for all servlets. Any servlet that requires a service environment
 * should extend this.
 * <p/>
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  11:43 AM
 */
public abstract class EnvServlet extends AbstractServlet {

    public ServiceEnvironmentImpl loadProperties2() throws IOException {
        ServiceEnvironmentImpl se2 = (ServiceEnvironmentImpl) getConfigurationLoader().load();
        return se2;
    }


    @Override
    public void loadEnvironment() throws IOException {
        if (environment == null) {
            setEnvironment(loadProperties2());
        }
    }

    /**
     * This will be invoked at init before anything else and should include code to seamlessly upgrade stores from earlier versions.
     * For instance, if a new column needs to be added to a table. This pre-supposes that the current user has the correct
     * permissions to alter the table, btw. This also updates the internal flag {@link #storeUpdatesDone} which should be
     * checks in overrides. If you override this method and call super, let super manage this flag. If it is true, do not
     * execute your method.
     */
    public abstract void storeUpdates() throws IOException, SQLException;

    public void processStoreCheck(Store store) throws SQLException {
        if (store instanceof SQLStore) {
            SQLStore sqlStore = (SQLStore) store;
            sqlStore.checkTable();
            sqlStore.checkColumns();
        }
    }

    public static boolean storeUpdatesDone = false;

}
