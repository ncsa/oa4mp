package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;
import org.qdl_lang.variables.QDLStem;

// Part of fix for https://github.com/ncsa/oa4mp/issues/283
public class MonitoredStemMC<V extends Monitored> extends StemConverter<V> {
    public MonitoredStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    public MonitoredStemMC(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected MonitoredKeys mc() {
        return (MonitoredKeys) keys;
    }

    /* Monitored attributes
    protected String lastAccessed = "last_accessed";
    String lastModified = "last_modified_ts";
    String creationTS = "creation_ts";
     */
    @Override
    public V fromMap(QDLStem stem, V v) {
        super.fromMap(stem, v);

        if (stem.containsKey(mc().creationTS())) {
            v.setCreationTS(toDate(stem, mc().creationTS()));
        }
        if (stem.containsKey(mc().lastModifiedTS())) {
            v.setLastModifiedTS(toDate(stem, mc().lastModifiedTS()));
        }
        if (stem.containsKey(mc().lastAccessed())) {
            v.setLastAccessed(toDate(stem, mc().lastAccessed()));
        }
        return v;
    }
    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        super.toMap(v, stem);
        setNonNullStemValue(stem, mc().creationTS(), v.getCreationTS());
        setNonNullStemValue(stem, mc().lastModifiedTS(), v.getLastModifiedTS());
        setNonNullStemValue(stem, mc().lastAccessed(), v.getLastAccessed());
        return stem;
    }
}
