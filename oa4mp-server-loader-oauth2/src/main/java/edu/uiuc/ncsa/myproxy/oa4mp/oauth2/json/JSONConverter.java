package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.json;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.json.JSONEntry;
import net.sf.json.JSON;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/20/19 at  9:29 AM
 */
public class JSONConverter<V extends JSONEntry> extends MapConverter<V> {
    public JSONConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    public JSONStoreKeys getJsonStoreKeys() {
        return (JSONStoreKeys) getKeys();
    }

    @Override
    public void toMap(V jsonEntry, ConversionMap<String, Object> map) {
        super.toMap(jsonEntry, map);
        map.put(getJsonStoreKeys().type(), jsonEntry.getType());
        if (map.containsKey(getJsonStoreKeys().content())) {
            Object obj = map.get(getJsonStoreKeys().content());
            if (obj instanceof JSON) {
                map.put(getJsonStoreKeys().content(), ((JSON) obj).toString(1));
            }
        }
        if (map.containsKey(getJsonStoreKeys().creationTimpestamp())) {
            map.put(getJsonStoreKeys().creationTimpestamp(), jsonEntry.getCreationTimestamp());

        } else {
            map.put(getJsonStoreKeys().creationTimpestamp(), new Date());
        }
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);

        value.setType(map.getString(getJsonStoreKeys().type()));
        if (map.containsKey(getJsonStoreKeys().creationTimpestamp())) {
            value.setCreationTimestamp(map.getDate(getJsonStoreKeys().creationTimpestamp()));
        } else {
            value.setCreationTimestamp(new Date());
        }
        if (map.containsKey(getJsonStoreKeys().lastModified())) {
            value.setLastModified(map.getDate(getJsonStoreKeys().lastModified()));
        } else {
            value.setLastModified(new Date());
        }

        String rawJSON = map.getString(getJsonStoreKeys().content());
        if (rawJSON == null || rawJSON.isEmpty()) {
            return value;
        }
        value.setRawContent(rawJSON);

        return value;
    }

}
