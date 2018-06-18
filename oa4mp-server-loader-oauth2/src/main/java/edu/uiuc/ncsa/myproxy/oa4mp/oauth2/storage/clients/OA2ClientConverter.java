package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientConfigurationUtil;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.util.Collection;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/17/14 at  1:29 PM
 */
public class OA2ClientConverter<V extends OA2Client> extends ClientConverter<V> {
    public OA2ClientConverter(IdentifiableProvider<V> identifiableProvider) {
        this(new OA2ClientKeys(), identifiableProvider);
    }


    public OA2ClientConverter(SerializationKeys keys, IdentifiableProvider<V> identifiableProvider) {
        super(keys, identifiableProvider);
    }

    public OA2ClientKeys getCK2() {
        return (OA2ClientKeys) keys;
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V otherV = super.fromMap(map, v);
        if (map.get(getCK2().callbackUri()) != null) {
            otherV.setCallbackURIs(jsonArrayToCollection(map, getCK2().callbackUri()));
        }
        if (map.get(getCK2().scopes()) != null) {
            otherV.setScopes(jsonArrayToCollection(map, getCK2().scopes()));
        }
        if (map.get(getCK2().publicClient()) != null) {
            otherV.setPublicClient(map.getBoolean(getCK2().publicClient()));
        }
        otherV.setRtLifetime(map.getLong(getCK2().rtLifetime()));
        if (map.containsKey(getCK2().issuer())) {
            otherV.setIssuer((String) map.get(getCK2().issuer()));
        }
        if (map.containsKey(getCK2().signTokens()) && map.get(getCK2().signTokens()) != null) {
            otherV.setSignTokens(map.getBoolean(getCK2().signTokens()));
        }
        JSONObject ldap = null;
        String zzz = map.getString(getCK2().ldap());
        if (map.containsKey(getCK2().ldap()) && !(zzz ==null ||  zzz.isEmpty())) {
            // make sure we don't try to JSON deserialize a null object either...
            // Lots to go wrong before we even get our hands on this.
            JSON temp = JSONSerializer.toJSON(map.get(getCK2().ldap()));

            if(!temp.isEmpty()) {
                if (!temp.isArray()) {
                    ldap = (JSONObject) temp;
                } else {
                    JSONArray array = (JSONArray) temp;
                    if (array.size() != 1) {
                        ServletDebugUtil.dbg(this,"Got " + array.size() + " LDAP configurations. Using first one only...");
                    //    throw new GeneralException("Error: multiple LDAP configurations encountered for id \"" + otherV.getIdentifierString() + "\". Convert manually.");
                    }
                    ldap = (JSONObject) array.get(0);

                }

            }
        }
        JSONObject cfg = null;
        if (map.containsKey(getCK2().cfg())) {
            String rawCfg = map.getString(getCK2().cfg());
            if(rawCfg != null && !rawCfg.isEmpty()) {
                cfg = JSONObject.fromObject(map.getString(getCK2().cfg()));
            }
            //otherV.setConfig(JSONObject.fromObject(map.getString(getCK2().cfg())));
        }
        if (ldap == null || ldap.isEmpty()) {
            // nix to do. Set the configuration object if it exists
            if(cfg == null){
                // so by this point, no configuration has been found either.
                cfg = new JSONObject();
            }
            OA2ClientConfigurationUtil.setSaved(cfg, true);


        } else {
            if (cfg == null) {
                cfg = new JSONObject();
                OA2ClientConfigurationUtil.setComment(cfg, "Created by converter from old LDAP entry");
            }
            OA2ClientConfigurationUtil.convertToNewConfiguration(ldap, cfg);
            // NOTE!! This next set of statement takes an existing LDAP and puts it back into the
            // configuration. This effectively updates the name (if needed) to ensure that conversion is
            // properly made to the new version, 4.0. If you remove this, you will delete the old LDAP
            // entries from the client. We will want to do this at some point.
            JSONArray ldaps = new JSONArray();
            ldaps.add(ldap);
            otherV.setLdaps(LDAPConfigurationUtil.fromJSON(ldaps));
        }
        if (cfg != null) {
            otherV.setConfig(cfg);
        }
        return otherV;
    }

    protected Collection<LDAPConfiguration> mapToLDAPS(ConversionMap<String, Object> map, String key) {
        JSONObject json = new JSONObject();
        JSON j = JSONSerializer.toJSON(map.get(key));
        json.put("ldap", j);
        return LDAPConfigurationUtil.fromJSON(j);
    }

    protected Collection<String> jsonArrayToCollection(ConversionMap<String, Object> map, String key) {
        JSONArray json = (JSONArray) JSONSerializer.toJSON(map.get(key));
        Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(json);
        return zzz;
    }


    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getCK2().rtLifetime(), client.getRtLifetime());
        if (client.getCallbackURIs() == null) {
            return;
        }
        map.put(getCK2().publicClient(), client.isPublicClient());
        JSONArray callbacks = new JSONArray();
        for (String s : client.getCallbackURIs()) {
            callbacks.add(s);
        }

        map.put(getCK2().callbackUri(), callbacks.toString());
        if (client.getIssuer() != null) {
            map.put(getCK2().issuer(), client.getIssuer());
        }
        map.put(getCK2().signTokens(), client.isSignTokens());
        if (client.getScopes() != null) {
            JSONArray scopes = new JSONArray();

            for (String s : client.getScopes()) {
                scopes.add(s);
            }

            map.put(getCK2().scopes(), scopes.toString());
        }
        if (client.getLdaps() != null && !client.getLdaps().isEmpty()) {
            map.put(getCK2().ldap(), LDAPConfigurationUtil.toJSON(client.getLdaps()).toString());
        }
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            map.put(getCK2().cfg(), client.getConfig().toString());
        }
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setRtLifetime(getJsonUtil().getJSONValueLong(json, getCK2().rtLifetime()));
        v.setIssuer(getJsonUtil().getJSONValueString(json, getCK2().issuer()));
        v.setSignTokens(getJsonUtil().getJSONValueBoolean(json, getCK2().signTokens()));
        v.setPublicClient(getJsonUtil().getJSONValueBoolean(json, getCK2().publicClient())); // JSON util returns false if missing key
        JSON cbs = (JSON) getJsonUtil().getJSONValue(json, getCK2().callbackUri());
        if (cbs != null && cbs instanceof JSONArray) {
            JSONArray array = (JSONArray) json.getJSONObject(getJSONComponentName()).get(getCK2().callbackUri());
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(array);
            v.setCallbackURIs(zzz);
        }

        JSON scopes = (JSON) getJsonUtil().getJSONValue(json, getCK2().scopes());
        if (scopes != null && scopes instanceof JSONArray) {
            JSONArray array = (JSONArray) json.getJSONObject(getJSONComponentName()).get(getCK2().scopes());
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(array);
            v.setScopes(zzz);
        }
        JSON ldaps = (JSON) getJsonUtil().getJSONValue(json, getCK2().ldap());
        if (ldaps != null) {
            v.setLdaps(LDAPConfigurationUtil.fromJSON(ldaps));
        }
        JSONObject config = (JSONObject) getJsonUtil().getJSONValue(json, getCK2().cfg());
        if (config != null) {
            v.setConfig(config);
        }

        return v;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);
        getJsonUtil().setJSONValue(json, getCK2().rtLifetime(), client.getRtLifetime());
        JSONArray callbacks = new JSONArray();
        Collection<String> callbackList = client.getCallbackURIs();
        for (String x : callbackList) {
            callbacks.add(x);
        }
        if (callbacks.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().callbackUri(), callbacks);
        }
        JSONArray scopes = new JSONArray();

        Collection<String> scopeList = client.getScopes();

        if (client.getIssuer() != null) {
            getJsonUtil().setJSONValue(json, getCK2().issuer(), client.getIssuer());
        }

        getJsonUtil().setJSONValue(json, getCK2().signTokens(), client.isSignTokens());
        getJsonUtil().setJSONValue(json, getCK2().publicClient(), client.isPublicClient());
        for (String x : scopeList) {
            scopes.add(x);
        }
        if (scopes.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().scopes(), scopes);
        }

        if (client.getLdaps() != null && !client.getLdaps().isEmpty()) {
            getJsonUtil().setJSONValue(json, getCK2().ldap(), LDAPConfigurationUtil.toJSON(client.getLdaps()));
        }

    }
}
