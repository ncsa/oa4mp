package org.oa4mp.server.loader.oauth2.cm.json;

import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import edu.uiuc.ncsa.security.util.json.JSONStore;

import javax.inject.Provider;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  10:25 AM
 */
public class JSONSQLStore<V extends JSONEntry> extends SQLStore<V> implements JSONStore<V> {
    public JSONSQLStore(ConnectionPool connectionPool, Table table, Provider<V> identifiableProvider, MapConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    @Override
    public String getCreationTSField() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void save(V value) {
        value.setLastModified(new Date());
        super.save(value);

    }
}
