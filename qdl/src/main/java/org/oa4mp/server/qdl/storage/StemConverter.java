package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import org.qdl_lang.variables.QDLStem;
import org.qdl_lang.variables.values.QDLValue;
import org.qdl_lang.variables.values.StringValue;

import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/20/20 at  7:06 AM
 */
public abstract class StemConverter<V extends Identifiable> extends MapConverter<V> {
    public StemConverter(MapConverter<V> mapConverter) {
        super(mapConverter.getKeys(), mapConverter.getProvider());
        parentMC = mapConverter;
    }
    public StemConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        return (V) getParentMC().fromMap(map, v);
    }


    /**
     * Parent map converter is the converter for the base object, i.e.. a {@link ConversionMap}
     * to a stored object.
     * @return
     */
    public MapConverter getParentMC() {
        return parentMC;
    }

    MapConverter parentMC;

    public boolean hasParentMapConverter() {
        return parentMC != null;
    }

    public V fromMap(QDLStem stem, V v) {
        v = createIfNeeded(v);
        v.setIdentifier(BasicIdentifier.newID(stem.getString(getKeys().identifier())));
        return v;
    }

    public QDLStem toMap(V v, QDLStem stem) {
        if (stem == null) {
            stem = new QDLStem();
        }
        stem.put(getKeys().identifier(), v.getIdentifierString());
        return stem;
    }

    /**
     * Checks that a string entry to the string exists and is not trivial
     *
     * @param stem
     * @param key
     * @return
     */
    protected boolean isStringKeyOK(QDLStem stem, String key) {
        return stem.containsKey(key) && !StringUtils.isTrivial(stem.getString(key));
    }

    /**
     * Checks if the time (as a long) is non-negative. If this is supposed to be a bona fide date,
     * then it cannot be negative.
     *
     * @param QDLStem
     * @param key
     * @return
     */
    protected boolean isTimeOk(QDLStem QDLStem, String key) {
        return QDLStem.containsKey(key) && -1L < QDLStem.getLong(key);
    }

    @Override
    public V fromMap(Map<String, Object> map, V v) {
        return fromMap(convertToStem(map), v);
/*
        if (map instanceof QDLStem) {
            return fromMap((QDLStem) map, v);
        }
        System.err.print("MapConverter.fromMap(): failed for " + v);
        throw new NotImplementedException(" not implement for non ConversionMap objects");

*/
    }

    public QDLStem convertToStem(Map<String, Object> map) {
        QDLStem stem = new QDLStem();
        for(String key : map.keySet()) {
            stem.put(key, QDLValue.asQDLValue(map.get(key)));
        }

        return stem;
    }
    @Override
    public void toMap(V value, Map<String, Object> data) {
/*

        if (data instanceof QDLStem) {
            toMap(value, (QDLStem) data);
            return;
        }
        System.err.print("MapConverter.fromMap(): failed for " + data);*/
        throw new NotImplementedException(" not implement for non ConversionMap objects");


    }

    /**
     * Convert a long in a stem entry to a date.
     *  <br/><b>Used in {@link #fromMap(QDLStem, Identifiable)}</b>
     * @param stem
     * @param key
     * @return
     */
    protected Date toDate(QDLStem stem, String key) {
        Date date = new Date();
        date.setTime(stem.get(key).asLong());
        return date;
    }

    /**
     * Get an attribute that is a stem list and convert it to a Java (generic) list
     *  <br/><b>Used in {@link #fromMap(QDLStem, Identifiable)}</b>
     * @param stem
     * @param key
     * @return
     */
    protected List toList(QDLStem stem, String key) {
        QDLStem target = stem.get(key).asStem();
        return target.getQDLList().toJSON();  // returns a JSONArray
    }

    /**
     * Convert a list in java object to a stem entry, setting it correctly. <br/><br/>
     * I.e. The result will be stem.key := c
     *  <br/><b>Used in {@link #toMap(Identifiable, QDLStem)}</b>
     * @param c
     * @param stem
     * @param key
     */
    protected void fromList(Collection c, QDLStem stem, String key) {
        QDLStem target = new QDLStem();
        if (c != null) {

            for (Object s : c) {
                if (s != null) {
                    target.listAdd(new StringValue(s.toString()));
                }
            }
            stem.put(key + QDLStem.STEM_INDEX_MARKER, target);
        }
    }

    /**
     * Convenience. If the value is not null, this will put it in the stem.
     * @param stem
     * @param key
     * @param value
     */
    protected void setNonNullStemValue(QDLStem stem, String key, Object value){
        if(value != null){
            stem.put(key, value);
        }
    }
}
