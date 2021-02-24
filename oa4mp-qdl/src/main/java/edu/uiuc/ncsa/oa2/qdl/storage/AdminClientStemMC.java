package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientKeys;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  6:21 AM
 */
public class AdminClientStemMC<V extends AdminClient> extends StemConverter<V> {
    public AdminClientStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    AdminClientKeys kk() {
        return (AdminClientKeys) keys;
    }

    @Override
    public V fromMap(StemVariable stem, V v) {
        v = super.fromMap(stem, v);
        if(stem.containsKey(kk().maxClients())){
            v.setMaxClients(stem.getLong(kk().maxClients()).intValue());
        }
       if(isStringKeyOK(stem, kk().issuer())){
           v.setIssuer(stem.getString(kk().issuer()));
       }
       if(isStringKeyOK(stem, kk().config())){
           v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));
       }
       if(stem.containsKey(kk().allowQDL())){
           v.setAllowQDL(stem.getBoolean(kk().allowQDL()));
       }
       if(isStringKeyOK(stem, kk().secret())){
           v.setSecret(stem.getString(kk().secret()));
       }
       if(stem.containsKey(kk().creationTS())){
           v.setCreationTS(toDate(stem, kk().creationTS()));
       }
       if(stem.containsKey(kk().lastModifiedTS())){
           v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));
       }
       if(isStringKeyOK(stem, kk().name())){
           v.setName(stem.getString(kk().name()));
       }
       if(isStringKeyOK(stem, kk().email())){
           v.setEmail(stem.getString(kk().email()));
       }
       if(isStringKeyOK(stem, kk().vo())){
           v.setVirtualOrganization(BasicIdentifier.newID(stem.getString(kk().vo())));
       }
        return v;
    }
    /*
          String maxClients = "max_clients";
      String issuer = "issuer";
      String config = "config";
      String allowQDL = "allow_qdl";
        String secret = "oauth_client_pubkey";
      String creationTS = "creation_ts";
      String name = "name";
      String email = "email";
      String lastModifiedTS = "last_modified_ts";
          String vo="vo";
       */
    @Override
    public StemVariable toMap(V v, StemVariable stem) {
        stem = super.toMap(v, stem);
        if (!isTrivial(v.getSecret())) {
            stem.put(kk().secret(), v.getSecret());
        }
        if (!isTrivial(v.getIssuer())) {
            stem.put(kk().issuer(), v.getIssuer());
        }
        if(v.getConfig() != null){
             stem.put(kk().config(), v.getConfig().toString());
        }
        stem.put(kk().maxClients(), Long.valueOf(v.getMaxClients()));
        stem.put(kk().allowQDL(), v.isAllowQDL());
        if (v.getCreationTS() != null) {
            stem.put(kk().creationTS(), v.getCreationTS().getTime());
        }
        if (!isTrivial(v.getName())) {
            stem.put(kk().name(), v.getName());
        }
        if (!isTrivial(v.getEmail())) {
            stem.put(kk().email(), v.getEmail());
        }
        if (v.getLastModifiedTS() != null) {
            stem.put(kk().lastModifiedTS(), v.getLastModifiedTS().getTime());
        }
        if (v.getVirtualOrganization()!= null) {
            stem.put(kk().vo(), v.getVirtualOrganization().toString());
        }
        return stem;
    }

}
