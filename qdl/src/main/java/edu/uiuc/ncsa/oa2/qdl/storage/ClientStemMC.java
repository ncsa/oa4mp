package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientKeys;
import edu.uiuc.ncsa.qdl.variables.QDLList;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

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
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        // Since these are created interactively, we have no choice really but to check each attribute.
        // We don't want cruft getting in to the store.
        /*
            List of base client keys  (9 of these)
         String creationTS = "creation_ts";
         String debugOn = "debug_on";
         String email = "email";
         String errorURL = "error_url";
         String homeURL = "home_url";
         String lastModifiedTS = "last_modified_ts";
         String name = "name";
         String proxyLimited = "proxy_limited";
         String secret = "oauth_client_pubkey";
             String ersatzInheritIDToken = "ersatz_inherit_id_token";

         */
        if (isTimeOk(stem, kk().creationTS())) {
            v.setCreationTS(toDate(stem, kk().creationTS()));
        }
        if(stem.containsKey(kk().ersatzInheritIDToken())){
            v.setErsatzInheritIDToken(stem.getBoolean(kk().ersatzInheritIDToken()));
        }
        if (stem.containsKey(kk().debugOn())) {
            v.setDebugOn(stem.getBoolean(kk().debugOn()));
        }
        if(stem.containsKey(kk().forwardScopesToProxy())){
            v.setForwardScopesToProxy(stem.getBoolean(kk().forwardScopesToProxy()));
        }
        if (isStringKeyOK(stem, kk().email())) {
            v.setEmail(stem.getString(kk().email()));
        }
        if (isStringKeyOK(stem, kk().errorURL())) {
            v.setErrorUri(stem.getString(kk().errorURL()));
        }
        if (isStringKeyOK(stem, kk().homeURL())) {
            v.setHomeUri(stem.getString(kk().homeURL()));
        }
        // 5
        if (isTimeOk(stem, kk().lastModifiedTS())) {
            v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));
        }
        if (isStringKeyOK(stem, kk().name())) {
            v.setName(stem.getString(kk().name()));
        }
        if (stem.containsKey(kk().proxyLimited())) {
            v.setProxyLimited(stem.getBoolean(kk().proxyLimited()));
        }
        if (isStringKeyOK(stem, kk().secret())) {
            v.setSecret(stem.getString(kk().secret()));
        }
        if(stem.containsKey(kk().rfc7523Client())){
             v.setServiceClient(stem.getBoolean(kk().rfc7523Client()));
        }
        if(stem.containsKey(kk().rfc7523ClientUsers())){
           v.setServiceClientUsers(toList(stem, kk().rfc7523ClientUsers()));
        }
        if(stem.containsKey(kk().jwks())){
            try {
                JSONWebKeys jwks = JSONWebKeyUtil.fromJSON(stem.getStem(kk().jwks()).toJSON());
                v.setJWKS(jwks);
            } catch (Throwable e) {
               if(DebugUtil.isEnabled()){ e.printStackTrace();}
               if(e instanceof RuntimeException){
                   throw (RuntimeException)e;
               }
               throw new GeneralException("could not convert to JSON web key.", e);
            }
        }
        // 9 attributes
        /* Alphabetical list of OA2 client attributes. (18 of these)
         String atLifetime = "at_lifetime";
         String audience="audience";
         String callback_uri = "callback_uri";
         String config = "cfg";
         String dfInterval="df_interval";
         String allowQDLCodeBlocks;

         String dfLifetime="df_lifetime";
         String ersatzClient = "ersatz_client";
         String extended_attributes = "extended_attributes";
         String issuer = "issuer";
         String ldap = "ldap";
         String maxATLifetime = "maxATLifetime";
         String maxRTLifetime = "maxRTLifetime";
         String proxyClaims="proxy_claims";
         String publicClient="public_client";

         String resource="resource";
         String rtLifetime = "rt_lifetime";
         String rtGracePeriod = "rt_grace_period";
         String scopes = "scopes";
         String signTokens="sign_tokens";
         String signTokens="skipServerScripts";
         String strictScopes="strict_scopes";
         String superTypes="super_types";
         */

        // OA2 client attributes
        if (stem.containsKey(kk().atLifetime())) {
            v.setAtLifetime(stem.getLong(kk().atLifetime()));
        }
        if (stem.containsKey(kk().audience())) {
            v.setAudience(toList(stem, kk().audience()));
            v.setAudience(toList(stem, kk().audience()));
        }
        if (stem.containsKey(kk().callbackUri())) {
            v.setCallbackURIs(toList(stem, kk().callbackUri()));
        }
        if (stem.containsKey(kk().cfg())) {
            QDLStem j = (QDLStem) stem.get(kk().cfg());
            v.setConfig((JSONObject) j.toJSON());
        }

        if (stem.containsKey(kk().dfInterval())) {
            v.setDfInterval(stem.getLong(kk().dfInterval()));
        }
        // 7
        if (stem.containsKey(kk().rtGracePeriod())) {
            v.setRtGracePeriod(stem.getLong(kk().rtGracePeriod()));
        }

        if (stem.containsKey(kk().dfLifetime())) {
            v.setDfLifetime(stem.getLong(kk().dfLifetime()));
        }
        if (stem.containsKey(kk().ersatzClient())) {
            v.setErsatzClient(stem.getBoolean(kk().ersatzClient()));
        }

        if (stem.containsKey(kk().ea())) {
            QDLStem j = (QDLStem) stem.get(kk().ea());
            v.setExtendedAttributes((JSONObject) j.toJSON());
        }
        if (isStringKeyOK(stem, kk().issuer())) {
            v.setIssuer(stem.getString(kk().issuer()));
        }
        if (stem.containsKey(kk().ldap())) {
            if (stem.get(kk().ldap()) instanceof QDLStem) {
                QDLStem ldap = (QDLStem) stem.get(kk().ldap());
                JSONArray array = (JSONArray) ldap.toJSON();
                v.setLdaps(getCC().getLdapConfigurationUtil().fromJSON(array));
            }
        }
        if (stem.containsKey(kk().extendsProvisioners())) {
            v.setExtendsProvisioners(stem.getBoolean(kk().extendsProvisioners()));
        }

        if (stem.containsKey(kk().prototypes())) {
            ArrayList<Identifier> ids = new ArrayList<>();
            List list = toList(stem, kk().prototypes()); // generic list of strings
            for (Object obj : list) {
                if (obj instanceof String) {
                    ids.add(BasicIdentifier.newID((String) obj));
                }
            }
            if (!ids.isEmpty()) {
                v.setPrototypes(ids);
            }
        }

        if (stem.containsKey(kk().proxyClaimsList())) {
            v.setProxyClaimsList(toList(stem, kk().proxyClaimsList()));
        }
        if (stem.containsKey(kk().proxyRequestScopes())) {
                 v.setProxyRequestScopes(toList(stem, kk().proxyRequestScopes()));
             }
        if (stem.containsKey(kk().publicClient())) {
            v.setPublicClient(stem.getBoolean(kk().publicClient()));
        }
        //  11
        if (stem.containsKey(kk().resource())) {
            v.setResource(toList(stem, kk().resource()));
        }
        if (stem.containsKey(kk().rtLifetime())) {
            v.setRtLifetime(stem.getLong(kk().rtLifetime()));
        }
        if (stem.containsKey(kk().idtLifetime())) {
            v.setIdTokenLifetime(stem.getLong(kk().idtLifetime()));
        }
        if (stem.containsKey(kk().maxIDTLifetime())) {
            v.setMaxIDTLifetime(stem.getLong(kk().maxIDTLifetime()));
        }

        if (stem.containsKey(kk().maxATLifetime())) {
            v.setMaxATLifetime(stem.getLong(kk().maxATLifetime()));
        }
        if (stem.containsKey(kk().maxRTLifetime())) {
            v.setMaxRTLifetime(stem.getLong(kk().maxRTLifetime()));
        }


        if (stem.containsKey(kk().scopes())) {
            v.setScopes(toList(stem, kk().scopes()));
        }
        if (stem.containsKey(kk().signTokens())) {
            v.setSignTokens(stem.getBoolean(kk().signTokens()));
        }
        if (stem.containsKey(kk().skipServerScripts())) {
            v.setSkipServerScripts(stem.getBoolean(kk().skipServerScripts()));
        }

        if (stem.containsKey(kk().strictScopes())) {
            v.setStrictscopes(stem.getBoolean(kk().strictScopes()));
        }
        // 15 attributes
        return v;
    }

    protected OA2ClientKeys kk() {
        return (OA2ClientKeys) keys;
    }

    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);
        // basic client attributes
        setNonNullStemValue(stem, kk().secret(), v.getSecret());
        setNonNullStemValue(stem, kk().debugOn(), v.isDebugOn());

        setNonNullStemValue(stem, kk().forwardScopesToProxy(), v.isForwardScopesToProxy());
        setNonNullStemValue(stem, kk().email(), v.getEmail());
        setNonNullStemValue(stem, kk().name(), v.getName());
        setNonNullStemValue(stem, kk().creationTS(), v.getCreationTS().getTime());
        if(v.hasJWKS()) {
            QDLStem ss = new QDLStem();
            ss.fromJSON(JSONWebKeyUtil.toJSON(v.getJWKS()));
            setNonNullStemValue(stem, kk().jwks(), ss);
        }
        // 6
        setNonNullStemValue(stem, kk().lastModifiedTS(), v.getLastModifiedTS().getTime());
        setNonNullStemValue(stem, kk().homeURL(), v.getHomeUri());
        setNonNullStemValue(stem, kk().errorURL(), v.getErrorUri());
        setNonNullStemValue(stem, kk().proxyLimited(), v.isProxyLimited());
        setNonNullStemValue(stem, kk().rfc7523Client(), v.isServiceClient());
        fromList(v.getServiceClientUsers(), stem, kk().rfc7523ClientUsers());
        setNonNullStemValue(stem, kk().extendsProvisioners(), v.isExtendsProvisioners());
        // 10 attributes

        // OA2 client attributes
        setNonNullStemValue(stem, kk().atLifetime(), v.getAtLifetime());
        setNonNullStemValue(stem, kk().idtLifetime(), v.getIdTokenLifetime());
        if (v.getAudience() != null && !v.getAudience().isEmpty()) {
            fromList(v.getAudience(), stem, kk().audience());
        }
        if (v.getCallbackURIs() != null && !v.getCallbackURIs().isEmpty()) {
            fromList(v.getCallbackURIs(), stem, kk().callbackUri());
        }
        if (v.getProxyClaimsList() != null && !v.getProxyClaimsList().isEmpty()) {
            fromList(v.getProxyClaimsList(), stem, kk().proxyClaimsList());
        }
        if (v.getProxyRequestScopes() != null && !v.getProxyRequestScopes().isEmpty()) {
            fromList(v.getProxyRequestScopes(), stem, kk().proxyRequestScopes());
        }

        if (v.getConfig() != null && !v.getConfig().isEmpty()) {
            QDLStem cfg = new QDLStem();
            cfg.fromJSON(v.getConfig());
            stem.put(kk().cfg(), cfg);
        }
        stem.put(kk().dfInterval(), v.getDfInterval());
        // 5
        stem.put(kk().dfLifetime(), v.getDfLifetime());
        if (v.getExtendedAttributes() != null && !v.getExtendedAttributes().isEmpty()) {
            QDLStem ea = new QDLStem();
            ea.fromJSON(v.getExtendedAttributes());
            stem.put(kk().ea(), ea);
        }
        stem.put(kk().maxIDTLifetime(), v.getMaxIDTLifetime());
        stem.put(kk().maxATLifetime(), v.getMaxATLifetime());
        stem.put(kk().maxRTLifetime(), v.getMaxRTLifetime());
        stem.put(kk().rtGracePeriod(), v.getRtGracePeriod());
        stem.put(kk().ersatzClient(), v.isErsatzClient());
        setNonNullStemValue(stem, kk().ersatzInheritIDToken(), v.isErsatzInheritIDToken());

        setNonNullStemValue(stem, kk().issuer(), v.getIssuer());
        if (v.getLdaps() != null && !v.getLdaps().isEmpty()) {
            JSONArray jsonArray = getCC().getLdapConfigurationUtil().toJSON(v.getLdaps());
            QDLStem ldap = new QDLStem();
            ldap.fromJSON(jsonArray);
            stem.put(kk().ldap(), ldap);
        }
        setNonNullStemValue(stem, kk().publicClient(), v.isPublicClient());
        // 12
        setNonNullStemValue(stem, kk().rtLifetime(), v.getRtLifetime());
        if (v.getResource() != null && !v.getResource().isEmpty()) {
            fromList(v.getResource(), stem, kk().resource());
        }
        if (v.getScopes() != null && !v.getScopes().isEmpty()) {
            fromList(v.getScopes(), stem, kk().scopes());
        }
        setNonNullStemValue(stem, kk().signTokens(), v.isSignTokens());
        setNonNullStemValue(stem, kk().skipServerScripts(), v.isSkipServerScripts());
        setNonNullStemValue(stem, kk().strictScopes(), v.useStrictScopes());
        if(v.hasPrototypes()){
            QDLList list = new QDLList();
            for(Identifier id : v.getPrototypes()){
                list.add(id.toString());
            }
            stem.put(kk().prototypes(), list);
        }
        // 15 attributes
        return stem;
    }

    OA2ClientConverter getCC() {
        return (OA2ClientConverter) parentMC;
    }
}
