package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/19/21 at  4:48 PM
 */
public class SQLVOStore<V extends VirtualOrganization> extends SQLStore<V> implements VOStore<V> {
    public SQLVOStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

}

