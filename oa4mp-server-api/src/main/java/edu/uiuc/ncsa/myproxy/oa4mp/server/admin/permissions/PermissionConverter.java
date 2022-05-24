package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONArray;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/11/16 at  1:58 PM
 */
public class PermissionConverter<V extends Permission> extends MapConverter<V> {
    public PermissionConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected PermissionKeys pk() {
        return (PermissionKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V value = super.fromMap(map, v);
        value.setAdminID(map.getIdentifier(pk().adminID()));
        value.setClientID(map.getIdentifier(pk().clientID()));
        if (map.containsKey(pk().ersatzID()) && map.get(pk().ersatzID())!=null) {
             JSONArray ids = JSONArray.fromObject(map.getString(pk().ersatzID()));
             // convert back to identifiers
            List<Identifier> x = new ArrayList<>();
            for(Object obj: ids){
                  if(obj instanceof String){
                      x.add(BasicIdentifier.newID((String)obj));
                  }
            }
            value.setErsatzChain(x);
        }
        value.setSubstitute(map.getBoolean(pk().substitute()));
        value.setApprove(map.getBoolean(pk().canApprove()));
        value.setCreate(map.getBoolean(pk().canCreate()));
        value.setDelete(map.getBoolean(pk().canRemove()));
        value.setRead(map.getBoolean(pk().readable()));
        value.setWrite(map.getBoolean(pk().writeable()));
        return value;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(pk().adminID(), value.getAdminID());
        data.put(pk().clientID(), value.getClientID());
        if (value.hasErsatzChain()) {
            // must be serialized as an array of strings
            JSONArray array = new JSONArray();

            for (Identifier id : value.getErsatzChain()) {
                array.add(id.toString());
            }
            data.put(pk().ersatzID(), array.toString());
        }
        data.put(pk().substitute(), value.canSubstitute());
        data.put(pk().canApprove(), value.isApprove());
        data.put(pk().canRemove(), value.isDelete());
        data.put(pk().writeable(), value.isWrite());
        data.put(pk().readable(), value.isRead());
        data.put(pk().canCreate(), value.isCreate());
    }
}
