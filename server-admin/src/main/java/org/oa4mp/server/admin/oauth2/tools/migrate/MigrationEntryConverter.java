package org.oa4mp.server.admin.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/26/24 at  11:48 AM
 */
public class MigrationEntryConverter<V extends MigrationEntry> extends MapConverter<V> {
    public MigrationEntryConverter(MigrateKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    @Override
    public MigrateKeys getKeys() {
        return (MigrateKeys) super.getKeys();
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        v = super.fromMap(map, v);

        if(testKey(map,getKeys().filename())){
            v.setFilename(map.getString(getKeys().filename()));
        }
        if(testKey(map, getKeys().error_message())){
            v.setErrorMessage(map.getString(getKeys().error_message()));
        }
        if(testKey(map,getKeys().import_code())){
            v.setImportCode(map.getInteger(getKeys().import_code()));
        }
        if(testKey(map,getKeys().create_ts())){
            v.setCreateTS(map.getDate(getKeys().create_ts()));
        }
        if(testKey(map,getKeys().import_ts())){
            v.setImportTS(map.getDate(getKeys().import_ts()));
        }
        if(testKey(map,getKeys().is_imported())){
            v.setImported(map.getBoolean(getKeys().is_imported()));
        }
        if(testKey(map,getKeys().store_type())){
            v.setStoreType(map.getString(getKeys().store_type()));
        }

        if(testKey(map,getKeys().path())){
            v.setPath(map.getString(getKeys().path()));
        }

            return v;
    }

    /**
     * Idiom for testing that the map contains the key AND the value is not null.
     * @param map
     * @param key
     * @return
     */
    protected boolean testKey(Map map,String key){
        return map.containsKey(key) && map.get(key)!=null;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(getKeys().import_code(), value.getImportCode() );
        if(value.hasError()) {
            data.put(getKeys().error_message(), value.getErrorMessage());
        }
        if(value.getCreateTS() != null){
            data.put(getKeys().create_ts(), value.getCreateTS());
        }
        if(value.getImportTS() != null){
            data.put(getKeys().import_ts(), value.getImportTS() );
        }
        data.put(getKeys().is_imported(), value.isImported());
        if(value.getPath() != null){
            data.put(getKeys().path(), value.getPath() );
        }
        if(value.getFilename() != null){
            data.put(getKeys().filename(), value.getFilename());
        }
        if(value.getStoreType() != null){
            data.put(getKeys().store_type(), value.getStoreType());
        }
    }

}

