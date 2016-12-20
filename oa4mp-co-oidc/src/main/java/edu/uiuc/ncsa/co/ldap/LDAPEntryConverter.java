package edu.uiuc.ncsa.co.ldap;

import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.oauth_2_0.server.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSONObject;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  3:30 PM
 */
public class LDAPEntryConverter<V extends LDAPEntry> extends MapConverter<V> {
    public LDAPEntryConverter(SerializationKeys keys, IdentifiableProvider<V> provider) {
        super(keys, provider);
    }

    protected LDAPEntryKeys getK(){return (LDAPEntryKeys) keys;}
    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        super.fromMap(map, v);
        v.setClientID(map.getIdentifier(getK().clientID()));
        LDAPConfigurationUtil.fromJSON(JSONObject.fromObject(map.getString(getK().ldap())));
        return v;
    }

    @Override
    public void toMap(V value, ConversionMap<String, Object> data) {
        super.toMap(value, data);
        data.put(getK().clientID(), value.clientID.toString());
        JSONObject json = LDAPConfigurationUtil.toJSON(value.getConfiguration());
        if(json != null) {
            data.put(getK().ldap(), json.toString());
        }
    }
}
