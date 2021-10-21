package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

/**
 * A {@link edu.uiuc.ncsa.qdl.variables.StemConverter} to convert stems and clients.
 * <p>Created by Jeff Gaynor<br>
 * on 12/20/20 at  7:24 AM
 */
public class ClientStemMC<V extends OA2Client> extends StemConverter<V> {
    public ClientStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }



    @Override
    public V fromMap(StemVariable stem, V v) {
        v = super.fromMap(stem, v);
        // Since these are created interactively, we have no choice really but to check each attribute.
        // We don't want cruft getting in to the store.
        if (isStringKeyOK(stem, kk().email())) {v.setEmail(stem.getString(kk().email()));}
        if (isTimeOk(stem, kk().creationTS())) {v.setCreationTS(toDate(stem, kk().creationTS()));}
        if (isStringKeyOK(stem, kk().errorURL())) {v.setErrorUri(stem.getString(kk().errorURL()));}
        if (isStringKeyOK(stem, kk().homeURL())) {v.setHomeUri(stem.getString(kk().homeURL()));}
        if (isTimeOk(stem, kk().lastModifiedTS())) {v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));}
        if (isStringKeyOK(stem, kk().name())) {v.setName(stem.getString(kk().name()));}
        if (stem.containsKey(kk().proxyLimited())) {v.setProxyLimited(stem.getBoolean(kk().proxyLimited()));}
        if (isStringKeyOK(stem, kk().secret())) {v.setSecret(stem.getString(kk().secret()));}
        /* Alphabetical list of OA2 client attributes.
         String atLifetime = "at_lifetime";
         String audience="audience";
         String callback_uri = "callback_uri";
         String config = "cfg";
         String dfInterval="df_interval";
         String dfLifetime="df_lifetime";
         String extended_attributes = "extended_attributes";
         String issuer = "issuer";
         String ldap = "ldap";
         String publicClient="public_client";
         String resource="resource";
         String rtLifetime = "rt_lifetime";
         String scopes = "scopes";
         String signTokens="sign_tokens";
         String strictScopes="strict_scopes";
         */

        // OA2 client attributes
        if (stem.containsKey(kk().atLifetime())) {v.setAtLifetime(stem.getLong(kk().atLifetime()));}
        if (stem.containsKey(kk().audience())) {v.setAudience(toList(stem, kk().audience()));}
        if (stem.containsKey(kk().callbackUri())) {v.setCallbackURIs(toList(stem, kk().callbackUri()));}
        if (stem.containsKey(kk().cfg())) {
            StemVariable j = (StemVariable) stem.get(kk().cfg());
            v.setConfig((JSONObject) j.toJSON());
        }
        if(stem.containsKey(kk().dfInterval())){v.setDfInterval(stem.getLong(kk().dfInterval()));}
        if(stem.containsKey(kk().dfLifetime())){v.setDfLifetime(stem.getLong(kk().dfLifetime()));}
        if (stem.containsKey( kk().ea())) {
            StemVariable j = (StemVariable) stem.get(kk().ea());
            v.setExtendedAttributes((JSONObject) j.toJSON());
        }
        if (isStringKeyOK(stem, kk().issuer())) {v.setIssuer(stem.getString(kk().issuer()));}
        if (stem.containsKey(kk().ldap())) {
            if (stem.get(kk().ldap()) instanceof StemVariable) {
                StemVariable ldap = (StemVariable) stem.get(kk().ldap());
                JSONArray array = (JSONArray) ldap.toJSON();
                v.setLdaps(getCC().getLdapConfigurationUtil().fromJSON(array));
            }
        if (stem.containsKey(kk().publicClient())) {v.setPublicClient(stem.getBoolean(kk().publicClient()));}
        if (stem.containsKey(kk().resource())) {v.setResource(toList(stem, kk().resource()));}
        if (stem.containsKey(kk().rtLifetime())) {v.setRtLifetime(stem.getLong(kk().rtLifetime()));}
        if (stem.containsKey(kk().scopes())) {v.setScopes(toList(stem, kk().scopes()));}
        if (stem.containsKey(kk().signTokens())) {v.setSignTokens(stem.getBoolean(kk().signTokens()));}
        if (stem.containsKey(kk().strictScopes())) {v.setStrictscopes(stem.getBoolean(kk().strictScopes()));}

        }
        return v;
    }

    protected OA2ClientKeys kk() {
        return (OA2ClientKeys) keys;
    }

    @Override
    public StemVariable toMap(V v, StemVariable stem) {
        stem = super.toMap(v, stem);
        // basic client attributes
        setNonNullStemValue(stem, kk().secret(), v.getSecret());
        setNonNullStemValue(stem, kk().email(), v.getEmail());
        setNonNullStemValue(stem, kk().name(), v.getName());
        setNonNullStemValue(stem, kk().creationTS(), v.getCreationTS().getTime());
        setNonNullStemValue(stem, kk().lastModifiedTS(), v.getLastModifiedTS().getTime());

        setNonNullStemValue(stem, kk().homeURL(), v.getHomeUri());
        setNonNullStemValue(stem, kk().errorURL(), v.getErrorUri());
        setNonNullStemValue(stem, kk().proxyLimited(), v.isProxyLimited());

        // OA2 client attributes
        setNonNullStemValue(stem, kk().atLifetime(), v.getAtLifetime());
        if(v.getAudience()!=null && !v.getAudience().isEmpty()){fromList(v.getAudience(), stem, kk().audience());}
        if(v.getCallbackURIs()!=null && !v.getCallbackURIs().isEmpty()){fromList(v.getCallbackURIs(), stem, kk().callbackUri());}
        if(v.getConfig() != null && !v.getConfig().isEmpty()){
            StemVariable cfg = new StemVariable();
            cfg.fromJSON(v.getConfig());
            stem.put(kk().cfg(), cfg);
        }
        stem.put(kk().dfInterval(), v.getDfInterval());
        stem.put(kk().dfLifetime(), v.getDfLifetime());
        if(v.getExtendedAttributes() != null && !v.getExtendedAttributes().isEmpty()){
            StemVariable ea = new StemVariable();
            ea.fromJSON(v.getExtendedAttributes());
            stem.put(kk().ea(), ea);
        }
        setNonNullStemValue(stem, kk().issuer(), v.getIssuer());
        if (v.getLdaps() != null && !v.getLdaps().isEmpty()) {
            JSONArray jsonArray = getCC().getLdapConfigurationUtil().toJSON(v.getLdaps());
            StemVariable ldap = new StemVariable();
            ldap.fromJSON(jsonArray);
            stem.put(kk().ldap(), ldap);
        }
        setNonNullStemValue(stem, kk().publicClient(), v.isPublicClient());
        setNonNullStemValue(stem, kk().rtLifetime(), v.getRtLifetime());
        if(v.getResource()!=null && !v.getResource().isEmpty()){fromList(v.getResource(), stem, kk().resource());}
        setNonNullStemValue(stem, kk().signTokens(), v.isSignTokens());
        if(v.getScopes()!=null && !v.getScopes().isEmpty()){fromList(v.getScopes(), stem, kk().scopes());};
        setNonNullStemValue(stem, kk().strictScopes(), v.useStrictScopes());

        return stem;
    }

    OA2ClientConverter getCC() {
        return (OA2ClientConverter) parentMC;
    }
}
