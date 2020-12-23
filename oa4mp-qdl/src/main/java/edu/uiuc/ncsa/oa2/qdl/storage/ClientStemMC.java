package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSON;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;

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
        if (isStringKeyOK(stem, kk().secret())) {
            v.setSecret(stem.getString(kk().secret()));
        }
        if (isStringKeyOK(stem, kk().email())) {
            v.setEmail(stem.getString(kk().email()));
        }

        if (isStringKeyOK(stem, kk().name())) {
            v.setName(stem.getString(kk().name()));
        }
        if (isTimeOk(stem, kk().creationTS())) {
            v.setCreationTS(toDate(stem, kk().creationTS()));
        }
        if (isTimeOk(stem, kk().lastModifiedTS())) {
            v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));
        }

        if (isStringKeyOK(stem, kk().homeURL())) {
            v.setHomeUri(stem.getString(kk().homeURL()));
        }

        if (isStringKeyOK(stem, kk().errorURL())) {
            v.setHomeUri(stem.getString(kk().errorURL()));
        }

        // no way to check booleans...
        if (stem.containsKey(kk().proxyLimited())) {
            v.setProxyLimited(stem.getBoolean(kk().proxyLimited()));
        }

        // OA2 client attributes
        if (stem.containsKey(kk().rtLifetime())) {
            v.setRtLifetime(stem.getLong(kk().rtLifetime()));
        }
        if (stem.containsKey(kk().publicClient())) {
            v.setPublicClient(stem.getBoolean(kk().publicClient()));
        }

        String cb_key = kk().callbackUri() + StemVariable.STEM_INDEX_MARKER;
        if (stem.containsKey(cb_key)) {
            v.setCallbackURIs(toList(stem, cb_key));
        }
        if (isStringKeyOK(stem, kk().issuer())) {
            v.setIssuer(stem.getString(kk().issuer()));
        }

        if(stem.containsKey(kk().signTokens())){
            v.setSignTokens(stem.getBoolean(kk().signTokens()));
        }
        if(stem.containsKey(kk().strictScopes())){
            v.setStrictscopes(stem.getBoolean(kk().strictScopes()));
        }

        String scopes_key = kk().scopes() + StemVariable.STEM_INDEX_MARKER;
        if(stem.containsKey(scopes_key)){
            v.setScopes(toList(stem, scopes_key));
        }
        if(isStringKeyOK(stem, kk().ldap())){
            JSON temp = JSONSerializer.toJSON(stem.getString(kk().ldap()));
            getCC().getLdapConfigurationUtil().fromJSON(temp);
        }
        if(isStringKeyOK(stem, kk().cfg())){
            JSONObject json = JSONObject.fromObject(stem.getString(kk().cfg()));
            v.setConfig(json);
        }
        if(isStringKeyOK(stem, kk().ea())){
            JSONObject json = JSONObject.fromObject(stem.getString(kk().ea()));
        }

        return v;
    }

    protected OA2ClientKeys kk() {
        return (OA2ClientKeys) keys;
    }

    @Override
    public StemVariable toMap(V v, StemVariable stem) {
     stem =   super.toMap(v, stem);
        // basic client attributes
        stem.put(kk().secret(), v.getSecret());
        stem.put(kk().email(), v.getEmail());
        stem.put(kk().name(), v.getName());
        stem.put(kk().creationTS(), v.getCreationTS().getTime());
        stem.put(kk().lastModifiedTS(), v.getLastModifiedTS().getTime());

        stem.put(kk().homeURL(), v.getHomeUri());
        stem.put(kk().errorURL(), v.getErrorUri());
        stem.put(kk().proxyLimited(), v.isProxyLimited());

        // OA2 client attributes
        stem.put(kk().rtLifetime(), v.getRtLifetime());
             /* if (v.getCallbackURIs() == null) {
                  return;
              }*/
        stem.put(kk().publicClient(), v.isPublicClient());
        // callbacks should be a stem list
        fromList(v.getCallbackURIs(), stem, kk().callbackUri());

        if (v.getIssuer() != null) {
            stem.put(kk().issuer(), v.getIssuer());
        }

        stem.put(kk().signTokens(), v.isSignTokens());
        stem.put(kk().strictScopes(), v.useStrictScopes());

        // scopes is a stem list
        fromList(v.getScopes(), stem, kk().scopes());

        if (v.getLdaps() != null && !v.getLdaps().isEmpty()) {
            stem.put(kk().ldap(), getCC().getLdapConfigurationUtil().toJSON(v.getLdaps()).toString());
        }
        if (v.getConfig() != null && !v.getConfig().isEmpty()) {
            stem.put(kk().cfg(), v.getConfig().toString()); // make it pretty at least...
        }
        if (v.getExtendedAttributes() != null && !v.getExtendedAttributes().isEmpty()) {
            stem.put(kk().ea(), v.getExtendedAttributes().toString());
        }
        return stem;
    }

    OA2ClientConverter getCC() {
        return (OA2ClientConverter) parentMC;
    }
}
