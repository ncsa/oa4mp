package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql;

import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  4:37:15 PM
 */
public class SQLClientStore<V extends Client> extends SQLStore<V> implements ClientStore<V> {
    public static final String DEFAULT_TABLENAME = "clients";


    public SQLClientStore(ConnectionPool connectionPool,
                          Table table,
                          Provider<V> idp,
                          MapConverter converter
                          ) {
        super(connectionPool, table, idp, converter);
    }

}
