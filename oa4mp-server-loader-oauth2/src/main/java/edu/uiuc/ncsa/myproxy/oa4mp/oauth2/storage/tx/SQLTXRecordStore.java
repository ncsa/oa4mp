package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx;

import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;

import javax.inject.Provider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  10:40 AM
 */
public class SQLTXRecordStore<V extends TXRecord> extends SQLStore<V>  implements TXStore<V>{
    public SQLTXRecordStore(ConnectionPool connectionPool,
                            TXRecordTable table,
                            Provider<V> identifiableProvider,
                            TXRecordConverter<V> converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

/*    @Override
    public MapConverter<V> getMapConverter() {
        return converter;
    }*/
}
