package org.oa4mp.server.api.admin.adminClient;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import org.oa4mp.delegation.server.storage.BaseClientSQLStore;

import javax.inject.Provider;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:52 PM
 */
public class AdminClientSQLStore<V extends AdminClient> extends BaseClientSQLStore<V> implements AdminClientStore<V> {
    public static final String DEFAULT_TABLENAME = "adminClients";
  
    public AdminClientSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
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

    @Override
    public V create() {
        V v= super.create();
        v.setDebugOn(true); //default for AC's
        return v;
    }

}
