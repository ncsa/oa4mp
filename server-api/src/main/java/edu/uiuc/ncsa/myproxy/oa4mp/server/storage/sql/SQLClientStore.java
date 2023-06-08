package edu.uiuc.ncsa.myproxy.oa4mp.server.storage.sql;

import edu.uiuc.ncsa.oa4mp.delegation.server.storage.BaseClientSQLStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.Client;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.util.Date;


/**
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  4:37:15 PM
 */
public class SQLClientStore<V extends Client> extends BaseClientSQLStore<V> implements ClientStore<V> {
    public static final String DEFAULT_TABLENAME = "clients";


    public SQLClientStore(ConnectionPool connectionPool,
                          Table table,
                          Provider<V> idp,
                          MapConverter converter
    ) {
        super(connectionPool, table, idp, converter);
    }


    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }

    @Override
    public void save(V value) {
        value.setLastModifiedTS(new java.sql.Timestamp(new Date().getTime()));
        super.save(value);
    }


}
