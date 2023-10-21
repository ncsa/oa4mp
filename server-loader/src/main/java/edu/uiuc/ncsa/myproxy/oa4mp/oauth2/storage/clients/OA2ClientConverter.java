package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import com.typesafe.config.Config;
import com.typesafe.config.ConfigFactory;
import com.typesafe.config.ConfigRenderOptions;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.clients.ClientConverter;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

import java.io.StringReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/17/14 at  1:29 PM
 */
public class OA2ClientConverter<V extends OA2Client> extends ClientConverter<V> {
    public OA2ClientConverter(IdentifiableProvider<V> identifiableProvider) {
        this(new OA2ClientKeys(), identifiableProvider);
    }


    public OA2ClientConverter(OA2ClientKeys keys, IdentifiableProvider<V> identifiableProvider) {
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
        if (map.get(getCK2().strictScopes()) != null) {
            otherV.setStrictscopes(map.getBoolean(getCK2().strictScopes()));
        }
        if (map.containsKey(getCK2().forwardScopesToProxy())) {
            otherV.setForwardScopesToProxy(map.getBoolean(getCK2().forwardScopesToProxy()));
        }
        if (map.get(getCK2().scopes()) != null) {
            otherV.setScopes(jsonArrayToCollection(map, getCK2().scopes()));
        }
        if (map.get(getCK2().proxyClaimsList()) != null) {
            otherV.setProxyClaimsList(jsonArrayToCollection(map, getCK2().proxyClaimsList()));
        }
        if(map.containsKey(getCK2().ersatzInheritIDToken())){
            otherV.setErsatzInheritIDToken(map.getBoolean(getCK2().ersatzInheritIDToken()));
        }
        if (map.get(getCK2().proxyRequestScopes()) == null) {
            JSONArray array = new JSONArray();
            array.add("*");
            otherV.setProxyRequestScopes(array);
        }else{
            otherV.setProxyRequestScopes(jsonArrayToCollection(map, getCK2().proxyRequestScopes()));
        }

        if (map.get(getCK2().audience()) != null) {
            otherV.setAudience(jsonArrayToCollection(map, getCK2().audience()));
        }
        if (map.containsKey(getCK2().extendsProvisioners())) {
            otherV.setExtendsProvisioners(map.getBoolean(getCK2().extendsProvisioners()));
        }
        if (map.get(getCK2().prototypes()) != null) {
            String raw = map.getString(getCK2().prototypes());
            JSONArray array;
            try {
                array = JSONArray.fromObject(raw);
            } catch (Throwable t) {
                array = new JSONArray();
                array.add(raw);
            }
            // Now, the type is List<Identifier> so convert as needed
            ArrayList<Identifier> ids = new ArrayList<>();
            for (Object obj : array) {
                if (obj instanceof Identifier) {
                    ids.add((Identifier) obj);
                } else {
                    if (obj instanceof String) {
                        ids.add(BasicIdentifier.newID((String) obj));
                    } else {
                        throw new IllegalArgumentException("Expected string or identifier, got \"" + obj + "\" of type " + obj.getClass().getSimpleName());
                    }
                }
            }
            otherV.setPrototypes(ids);
        }
        if (map.get(getCK2().resource()) != null) {
            Collection<String> collection = jsonArrayToCollection(map, getCK2().resource()); // This is now strings.

            JSONArray jsonArray = new JSONArray();
            for (String x : collection) {
                jsonArray.add(URI.create(x));
            }
            otherV.setAudience(jsonArray);
        }
        if (map.get(getCK2().publicClient()) != null) {
            otherV.setPublicClient(map.getBoolean(getCK2().publicClient()));
        }
        if (map.get(getCK2().ersatzClient()) != null) {
            otherV.setErsatzClient(map.getBoolean(getCK2().ersatzClient()));
        }
        otherV.setRtLifetime(map.getLong(getCK2().rtLifetime()));
        otherV.setIdTokenLifetime(map.getLong(getCK2().idtLifetime()));
        otherV.setRtGracePeriod(map.getLong(getCK2().rtGracePeriod()));
        otherV.setDfLifetime(map.getLong(getCK2().dfLifetime()));
        otherV.setDfInterval(map.getLong(getCK2().dfInterval()));
        if(map.containsKey(getCK2().maxATLifetime()) && map.get(getCK2().maxATLifetime()) != null) {
            otherV.setMaxATLifetime(map.getLong(getCK2().maxATLifetime()));
        }
        if(map.containsKey(getCK2().maxRTLifetime()) && map.get(getCK2().maxRTLifetime()) != null) {
            otherV.setMaxRTLifetime(map.getLong(getCK2().maxRTLifetime()));
        }
        if(map.containsKey(getCK2().maxIDTLifetime()) && map.get(getCK2().maxIDTLifetime()) != null) {
            // a null value is returned as 0.
            otherV.setMaxIDTLifetime(map.getLong(getCK2().maxIDTLifetime()));
        }
        otherV.setSkipServerScripts(map.getBoolean(getCK2().skipServerScripts()));

        // In certain legacy cases, this may end up being populated with a null. Treat it like
        // a -1 (which means it isn't set, so don't use this in calculations)
        if (map.containsKey(getCK2().atLifetime()) && map.get(getCK2().atLifetime()) != null) {
            otherV.setAtLifetime(map.getLong(getCK2().atLifetime()));

        }
        if (map.containsKey(getCK2().issuer())) {
            otherV.setIssuer((String) map.get(getCK2().issuer()));
        }
        if (map.containsKey(getCK2().signTokens()) && map.get(getCK2().signTokens()) != null) {
            otherV.setSignTokens(map.getBoolean(getCK2().signTokens()));
        }

        JSONObject ldap = null;
        String zzz = map.getString(getCK2().ldap());
        if (map.containsKey(getCK2().ldap()) && !(zzz == null || zzz.isEmpty())) {
            // make sure we don't try to JSON deserialize a null object either...
            // Lots to go wrong before we even get our hands on this.
            JSON temp = JSONSerializer.toJSON(map.get(getCK2().ldap()));

            if (!temp.isEmpty()) {
                if (!temp.isArray()) {
                    ldap = (JSONObject) temp;
                } else {
                    JSONArray array = (JSONArray) temp;
                    if (array.size() != 1) {
                        ServletDebugUtil.trace(this, "Got " + array.size() + " LDAP configurations. Using first one only...");
                        //    throw new GeneralException("Error: multiple LDAP configurations encountered for id \"" + otherV.getIdentifierString() + "\". Convert manually.");
                    }
                    ldap = (JSONObject) array.get(0);

                }

            }
        }
        if (map.containsKey(getCK2().ea())) {
            String rawCfg = map.getString(getCK2().ea());
            if (!isTrivial(rawCfg)) {
                otherV.setExtendedAttributes(JSONObject.fromObject(rawCfg));
            }
        }
        JSONObject cfg = null;
        if (map.containsKey(getCK2().cfg())) {
            String rawCfg = map.getString(getCK2().cfg());
            if (rawCfg != null && !rawCfg.isEmpty()) {
                //    cfg = JSONObject.fromObject(map.getString(getCK2().cfg()));
                // Extra hoop allows us to process HOCON format in addition to JSON.
                String tempcfg = map.getString(getCK2().cfg());
                if (!isTrivial(tempcfg)) {
                    StringReader stringReader = new StringReader(tempcfg);
                    Config conf = ConfigFactory.parseReader(stringReader);
                    String rawJSON = conf.root().render(ConfigRenderOptions.concise());
                    cfg = JSONObject.fromObject(rawJSON);
                    otherV.setRawConfig(tempcfg);
                    //      otherV.setConfig(cfg);
                }
            }
            //otherV.setConfig(JSONObject.fromObject(map.getString(getCK2().cfg())));
        }

        if (ldap == null || ldap.isEmpty()) {
            // nix to do. Set the configuration object if it exists
            if (cfg == null) {
                // so by this point, no configuration has been found either.
                cfg = new JSONObject();
            }
            //         OA2ClientFunctorScriptsUtil.setSaved(cfg, true);


        } else {
            // This next block was to convert to new format, but the monitor which pings the system regularly
            // just ended up filling up the logs (since it would get the client, but then not do anything after
            // the initial call, hence never saving the changes.
            // Seriously not worth it do have this here.
          /*  if (cfg == null) {
                cfg = new JSONObject();
                OA2ClientFunctorScriptsUtil.setComment(cfg, "Created by converter from old LDAP entry");
                ServletDebugUtil.trace(this,"starting to convert client with id=" + otherV.getIdentifierString());
                OA2ClientFunctorScriptsUtil.convertToNewConfiguration(ldap, cfg);
            }*/

            // NOTE!! This next set of statement takes an existing LDAP and puts it back into the
            // configuration. This effectively updates the name (if needed) to ensure that conversion is
            // properly made to the new version, 4.0. If you remove this, you will delete the old LDAP
            // entries from the client. We will want to do this at some point.
            JSONArray ldaps = new JSONArray();
            ldaps.add(ldap);

            otherV.setLdaps(getLdapConfigurationUtil().fromJSON(ldaps));
        }
        if (cfg != null) {
            otherV.setConfig(cfg);
        }
        return otherV;
    }

    public LDAPConfigurationUtil getLdapConfigurationUtil() {
        if (ldapConfigurationUtil == null) {
            ldapConfigurationUtil = new LDAPConfigurationUtil();
        }
        return ldapConfigurationUtil;
    }

    LDAPConfigurationUtil ldapConfigurationUtil;


    @Override
    public void toMap(V client, ConversionMap<String, Object> map) {
        super.toMap(client, map);
        map.put(getCK2().rtLifetime(), client.getRtLifetime());
        map.put(getCK2().rtGracePeriod(), client.getRtGracePeriod());
        map.put(getCK2().atLifetime(), client.getAtLifetime());
        map.put(getCK2().idtLifetime(), client.getIdTokenLifetime());
        map.put(getCK2().dfLifetime(), client.getDfLifetime());
        map.put(getCK2().dfInterval(), client.getDfInterval());
        map.put(getCK2().maxATLifetime(), client.getMaxATLifetime());
        map.put(getCK2().maxRTLifetime(), client.getMaxRTLifetime());
        map.put(getCK2().maxIDTLifetime(), client.getMaxIDTLifetime());
        map.put(getCK2().skipServerScripts(), client.isSkipServerScripts());
        map.put(getCK2().forwardScopesToProxy(), client.isForwardScopesToProxy());
        if (client.getCallbackURIs() == null) {
            return;
        }
        map.put(getCK2().publicClient(), client.isPublicClient());
        map.put(getCK2().ersatzClient(), client.isErsatzClient());
        map.put(getCK2().extendsProvisioners(), client.isExtendsProvisioners());
        if (client.hasPrototypes()) {
            if (!client.getPrototypes().isEmpty()) {
                // These are ids. Return as strings or they get serizalized wrong
                JSONArray array = new JSONArray();
                for (Identifier id : client.getPrototypes()) {
                    array.add(id.toString());
                }
                map.put(getCK2().prototypes(), array.toString());
            }
        }
        JSONArray callbacks = new JSONArray();
        for (String s : client.getCallbackURIs()) {
            callbacks.add(s);
        }

        map.put(getCK2().callbackUri(), callbacks.toString());
        if (client.getIssuer() != null) {
            map.put(getCK2().issuer(), client.getIssuer());
        }
        map.put(getCK2().signTokens(), client.isSignTokens());
        map.put(getCK2().strictScopes(), client.useStrictScopes());
        if (client.getScopes() != null) {
            JSONArray scopes = new JSONArray();
            for (String s : client.getScopes()) {
                scopes.add(s);
            }
            map.put(getCK2().scopes(), scopes.toString());
        }
        if (client.getProxyClaimsList() != null) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(client.getProxyClaimsList());
            map.put(getCK2().proxyClaimsList(), jsonArray.toString());
        }

        if (client.getProxyRequestScopes() != null) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(client.getProxyRequestScopes());
            map.put(getCK2().proxyRequestScopes(), jsonArray.toString());
        } else {
            // sets default for missing proxy request scopes to all.
            JSONArray jsonArray = new JSONArray();
            jsonArray.add("*");
            map.put(getCK2().proxyRequestScopes(), jsonArray.toString());
        }
        if (client.getAudience() != null) {
            JSONArray aud = new JSONArray();
            for (String s : client.getAudience()) {
                aud.add(s);
            }
            map.put(getCK2().audience(), aud.toString());
        }
        if (client.getResource() != null) {
            JSONArray resources = new JSONArray();
            for (URI s : client.getResource()) {
                resources.add(s.toString());
            }
            map.put(getCK2().audience(), resources.toString());
        }

        if (client.getLdaps() != null && !client.getLdaps().isEmpty()) {
            map.put(getCK2().ldap(), getLdapConfigurationUtil().toJSON(client.getLdaps()).toString());
        }
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            map.put(getCK2().cfg(), client.getConfig().toString()); // make it pretty at least...
        }
        if (client.getExtendedAttributes() != null && !client.getExtendedAttributes().isEmpty()) {
            map.put(getCK2().ea(), client.getExtendedAttributes().toString());
        }
        map.put(getCK2().ersatzInheritIDToken(), client.isErsatzInheritIDToken());
    }

    @Override
    public V fromJSON(JSONObject json) {
        V v = super.fromJSON(json);
        v.setRtLifetime(getJsonUtil().getJSONValueLong(json, getCK2().rtLifetime()));
        v.setRtGracePeriod(getJsonUtil().getJSONValueLong(json, getCK2().rtGracePeriod()));
        if (json.containsKey(getCK2().atLifetime())) {
            v.setAtLifetime(getJsonUtil().getJSONValueLong(json, getCK2().atLifetime()));
        }
        if (json.containsKey(getCK2().idtLifetime())) {
            v.setIdTokenLifetime(getJsonUtil().getJSONValueLong(json, getCK2().idtLifetime()));
        }
        if (json.containsKey(getCK2().maxIDTLifetime())) {
            v.setMaxIDTLifetime(getJsonUtil().getJSONValueLong(json, getCK2().maxIDTLifetime()));
        }

        if (json.containsKey(getCK2().dfLifetime())) {
            v.setDfLifetime(getJsonUtil().getJSONValueLong(json, getCK2().dfLifetime()));
        }
        if(json.containsKey(getCK2().ersatzInheritIDToken())){
            v.setErsatzInheritIDToken(getJsonUtil().getJSONValueBoolean(json, getCK2().ersatzInheritIDToken()));
        }
        if (json.containsKey(getCK2().dfInterval())) {
            v.setDfInterval(getJsonUtil().getJSONValueLong(json, getCK2().dfInterval()));
        }
        if (json.containsKey(getCK2().maxATLifetime())) {
            v.setMaxATLifetime(getJsonUtil().getJSONValueLong(json, getCK2().maxATLifetime()));
        }
        if (json.containsKey(getCK2().maxRTLifetime())) {
            v.setMaxRTLifetime(getJsonUtil().getJSONValueLong(json, getCK2().maxRTLifetime()));
        }
        if (json.containsKey(getCK2().forwardScopesToProxy())) {
            v.setForwardScopesToProxy(getJsonUtil().getJSONValueBoolean(json, getCK2().forwardScopesToProxy()));
        }
        if (json.containsKey(getCK2().proxyRequestScopes())) {
            v.setProxyRequestScopes(getJsonUtil().getJSONArray(json, getCK2().proxyRequestScopes()));
        }
        if (json.containsKey(getCK2().prototypes())) {
            if (!json.getJSONArray(getCK2().prototypes()).isEmpty()) {
                JSONArray array = json.getJSONArray(getCK2().prototypes());

                ArrayList<Identifier> ids = new ArrayList<>();
                for (Object obj : array) {
                    if (obj instanceof String) {
                        ids.add(BasicIdentifier.newID((String) obj));
                    }
                }
                v.setPrototypes(ids);
            }
        }
        if (json.containsKey(getCK2().extendsProvisioners())) {
            v.setExtendsProvisioners(json.getBoolean(getCK2().extendsProvisioners()));
        }
        v.setIssuer(getJsonUtil().getJSONValueString(json, getCK2().issuer()));
        v.setSignTokens(getJsonUtil().getJSONValueBoolean(json, getCK2().signTokens()));
        v.setPublicClient(getJsonUtil().getJSONValueBoolean(json, getCK2().publicClient())); // JSON util returns false if missing key
        if (json.containsKey(getCK2().strictScopes())) {
            v.setStrictscopes(getJsonUtil().getJSONValueBoolean(json, getCK2().strictScopes())); // JSON util returns false if missing key
        }
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
        JSON aud = (JSON) getJsonUtil().getJSONValue(json, getCK2().audience());
        if (aud != null && aud instanceof JSONArray) {
            JSONArray array = (JSONArray) json.getJSONObject(getJSONComponentName()).get(getCK2().audience());
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(array);
            v.setAudience(zzz);
        }
        JSON resources = (JSON) getJsonUtil().getJSONValue(json, getCK2().resource());
        if (resources != null && !resources.isEmpty()) {
            JSONArray array = (JSONArray) json.getJSONObject(getJSONComponentName()).get(getCK2().resource());
            Collection<String> zzz = (Collection<String>) JSONSerializer.toJava(array);
            List<URI> x = new LinkedList<>();
            for (String s : zzz) {
                x.add(URI.create(s));
            }
            v.setResource(x);
        }


        JSON ldaps = (JSON) getJsonUtil().getJSONValue(json, getCK2().ldap());
        if (ldaps != null) {
            v.setLdaps(getLdapConfigurationUtil().fromJSON(ldaps));
        }
        JSONObject config = (JSONObject) getJsonUtil().getJSONValue(json, getCK2().cfg());
        if (config != null) {
            v.setConfig(config);
            v.setRawConfig(config.toString());
        }
        v.setExtendedAttributes(json.getJSONObject(getCK2().ea()));

        return v;
    }

    @Override
    public void toJSON(V client, JSONObject json) {
        super.toJSON(client, json);
        getJsonUtil().setJSONValue(json, getCK2().rtLifetime(), client.getRtLifetime());
        getJsonUtil().setJSONValue(json, getCK2().idtLifetime(), client.getIdTokenLifetime());
        getJsonUtil().setJSONValue(json, getCK2().rtGracePeriod(), client.getRtGracePeriod());
        getJsonUtil().setJSONValue(json, getCK2().dfLifetime(), client.getDfLifetime());
        getJsonUtil().setJSONValue(json, getCK2().dfInterval(), client.getDfInterval());
        getJsonUtil().setJSONValue(json, getCK2().maxATLifetime(), client.getMaxATLifetime());
        getJsonUtil().setJSONValue(json, getCK2().maxRTLifetime(), client.getMaxRTLifetime());
        getJsonUtil().setJSONValue(json, getCK2().maxIDTLifetime(), client.getMaxIDTLifetime());
        getJsonUtil().setJSONValue(json, getCK2().forwardScopesToProxy(), client.isForwardScopesToProxy());
        getJsonUtil().setJSONValue(json, getCK2().proxyRequestScopes(), client.getProxyRequestScopes());
        getJsonUtil().setJSONValue(json, getCK2().ersatzInheritIDToken(), client.isErsatzInheritIDToken());
        JSONArray callbacks = new JSONArray();
        Collection<String> callbackList = client.getCallbackURIs();
        for (String x : callbackList) {
            callbacks.add(x);
        }
        getJsonUtil().setJSONValue(json, getCK2().extendsProvisioners(), client.isExtendsProvisioners());
        if (client.hasRequestScopes()) {
            JSONArray jsonArray = new JSONArray();
            jsonArray.addAll(client.getProxyRequestScopes());
            getJsonUtil().setJSONValue(json, getCK2().prototypes(), jsonArray);
        }
        if (client.hasPrototypes()) {
            JSONArray array = new JSONArray();
            for (Identifier identifier : client.getPrototypes()) {
                array.add(identifier.toString());
            }
            getJsonUtil().setJSONValue(json, getCK2().prototypes(), array);
        }

        if (callbacks.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().callbackUri(), callbacks);
        }
        JSONArray aud = new JSONArray();
        Collection<String> audience = client.getAudience();
        if (audience != null) {
            for (String x : audience) {
                aud.add(x);
            }
        }
        if (aud.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().audience(), aud);
        }

        JSONArray res = new JSONArray();
        List<URI> resources = client.getResource();
        if (resources != null) {
            for (URI uri : resources) {
                res.add(uri.toString());

            }
        }
        if (res.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().resource(), res);
        }

        // Fix CIL-519: converter must serialize configuration object in toJSON call
        if (client.getConfig() != null && !client.getConfig().isEmpty()) {
            //json.put(getCK2().cfg(), client.getConfig());
            getJsonUtil().setJSONValue(json, getCK2().cfg(), client.getConfig());
        }

        if (client.getIssuer() != null) {
            getJsonUtil().setJSONValue(json, getCK2().issuer(), client.getIssuer());
        }

        getJsonUtil().setJSONValue(json, getCK2().signTokens(), client.isSignTokens());
        getJsonUtil().setJSONValue(json, getCK2().publicClient(), client.isPublicClient());
        getJsonUtil().setJSONValue(json, getCK2().strictScopes(), client.useStrictScopes());

        JSONArray scopes = new JSONArray();
        Collection<String> scopeList = client.getScopes();

        for (String x : scopeList) {
            scopes.add(x);
        }
        if (scopes.size() != 0) {
            getJsonUtil().setJSONValue(json, getCK2().scopes(), scopes);
        }

        if (client.getLdaps() != null && !client.getLdaps().isEmpty()) {
            getJsonUtil().setJSONValue(json, getCK2().ldap(), getLdapConfigurationUtil().toJSON(client.getLdaps()));
        }

        if (client.getExtendedAttributes() != null && !client.getExtendedAttributes().isEmpty()) {
            getJsonUtil().setJSONValue(json, getCK2().ea(), client.getExtendedAttributes());
        }

    }
}
