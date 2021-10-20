package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

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

    public MapConverter getParentMC() {
        return parentMC;
    }

    MapConverter parentMC;

    public boolean hasParentMapConverter() {
        return parentMC != null;
    }

    public V fromMap(StemVariable stem, V v) {
        v = createIfNeeded(v);
        v.setIdentifier(BasicIdentifier.newID(stem.getString(getKeys().identifier())));
        return v;
    }

    public StemVariable toMap(V v, StemVariable stem) {
        if (stem == null) {
            stem = new StemVariable();
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
    protected boolean isStringKeyOK(StemVariable stem, String key) {
        return stem.containsKey(key) && !StringUtils.isTrivial(stem.getString(key));
    }

    /**
     * Checks if the time (as a long) is non-negative. If this is supposed to be a bona fide date,
     * then it cannot be negative.
     *
     * @param stemVariable
     * @param key
     * @return
     */
    protected boolean isTimeOk(StemVariable stemVariable, String key) {
        return stemVariable.containsKey(key) && -1L < stemVariable.getLong(key);
    }

    @Override
    public V fromMap(Map<String, Object> map, V v) {
        if (map instanceof StemVariable) {
            return fromMap((StemVariable) map, v);
        }
        System.err.print("MapConverter.fromMap(): failed for " + v);
        throw new NotImplementedException("Error: not implement for non ConversionMap objects");

    }

    @Override
    public void toMap(V value, Map<String, Object> data) {
        if (data instanceof StemVariable) {
            toMap(value, (StemVariable) data);
            return;
        }
        System.err.print("MapConverter.fromMap(): failed for " + data);
        throw new NotImplementedException("Error: not implement for non ConversionMap objects");

    }

    /**
     * Convert a long in a stem entry to a date.
     *  <br/><b>Used in {@link #fromMap(StemVariable, Identifiable)}</b>
     * @param stem
     * @param key
     * @return
     */
    protected Date toDate(StemVariable stem, String key) {
        Date date = new Date();
        date.setTime(stem.getLong(key));
        return date;
    }

    /**
     * Get an attribute that is a stem list and convert it to a Java (generic) list
     *  <br/><b>Used in {@link #fromMap(StemVariable, Identifiable)}</b>
     * @param stem
     * @param key
     * @return
     */
    protected List toList(StemVariable stem, String key) {
        StemVariable target = (StemVariable) stem.get(key);
        return target.getStemList().toJSON();  // returns a JSONArray
    }

    /**
     * Convert a list in java object to a stem entry, setting it correctly.
     *  <br/><b>Used in {@link #toMap(Identifiable, StemVariable)}</b>
     * @param c
     * @param stem
     * @param key
     */
    protected void fromList(Collection c, StemVariable stem, String key) {
        StemVariable target = new StemVariable();
        if (c != null) {

            for (Object s : c) {
                if (s != null) {
                    target.listAppend(s.toString());
                }
            }
            stem.put(key + StemVariable.STEM_INDEX_MARKER, target);
        }
    }


    protected void setNonNullStemValue(StemVariable stem, String key, Object value){
        if(value != null){
            stem.put(key, value);
        }
    }
}
