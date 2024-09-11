package org.oa4mp.server.qdl.storage;

import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.qdl_lang.variables.QDLStem;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;

import java.net.URI;

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
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        /*
        String allowQDL = "allow_qdl";
        String config = "config";
        String issuer = "issuer";
        String maxClients = "max_clients";
        String notifyOnNewClientCreate="new_client_notify";
        String vo="vo";
        String voURI="vo_uri";
           */

        if (stem.containsKey(kk().creationTS())) {
            v.setCreationTS(toDate(stem, kk().creationTS()));
        }
        if (isStringKeyOK(stem, kk().email())) {
            v.setEmail(stem.getString(kk().email()));
        }
        if (stem.containsKey(kk().debugOn())) {
            v.setDebugOn(stem.getBoolean(kk().debugOn()));
        }
        if (stem.containsKey(kk().lastModifiedTS())) {
            v.setLastModifiedTS(toDate(stem, kk().lastModifiedTS()));
        }
        if (isStringKeyOK(stem, kk().name())) {
            v.setName(stem.getString(kk().name()));
        }
        if (isStringKeyOK(stem, kk().secret())) {
            v.setSecret(stem.getString(kk().secret()));
        }

        // Attributes specific to admin clients
        if (stem.containsKey(kk().allowQDL())) {
            v.setAllowQDL(stem.getBoolean(kk().allowQDL()));
        }
        if(stem.containsKey(kk().allowQDLCodeBlocks())){
               v.setAllowQDLCodeBlocks(stem.getBoolean(kk().allowQDLCodeBlocks()));
           }
        if (stem.containsKey(kk().listUsers())) {
            v.setListUsers(stem.getBoolean(kk().listUsers()));
        }
        if (stem.containsKey(kk().listUsersInOtherClients())) {
            v.setListUsersInOtherClients(stem.getBoolean(kk().listUsersInOtherClients()));
        }
        if (stem.containsKey(kk().allowCustomIDs())) {
             v.setAllowCustomIDs(stem.getBoolean(kk().allowCustomIDs()));
         }
        if (stem.containsKey(kk().useTimestampsInIds())) {
               v.setUseTimestampInIDs(stem.getBoolean(kk().useTimestampsInIds()));
           }

        if (stem.containsKey(kk().generateIDs())) {
             v.setGenerateIDs(stem.getBoolean(kk().generateIDs()));
         }
        if (stem.containsKey(kk().idHead())) {
             v.setIdHead(URI.create(stem.getString(kk().idHead())));
         }
        if (isStringKeyOK(stem, kk().config())) {
            v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));
        }
        if (stem.containsKey(kk().config())) {
            v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));
        }
        if (isStringKeyOK(stem, kk().issuer())) {
            v.setIssuer(stem.getString(kk().issuer()));
        }
        if (stem.containsKey(kk().maxClients())) {
            v.setMaxClients(stem.getLong(kk().maxClients()).intValue());
        }
        if (isStringKeyOK(stem, kk().vo())) {
            v.setVirtualOrganization(BasicIdentifier.newID(stem.getString(kk().voURI())));
        }
        if (isStringKeyOK(stem, kk().voURI())) {
            v.setExternalVOName(stem.getString(kk().voURI()));
        }

        return v;
    }

    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);
        setNonNullStemValue(stem, kk().creationTS(), v.getCreationTS().getTime());
        setNonNullStemValue(stem, kk().email(), v.getEmail());
        stem.put(kk().debugOn(), v.isDebugOn());
        setNonNullStemValue(stem, kk().lastModifiedTS(), v.getLastModifiedTS().getTime());
        setNonNullStemValue(stem, kk().name(), v.getName());
        setNonNullStemValue(stem, kk().secret(), v.getSecret());

        stem.put(kk().allowQDL(), v.isAllowQDL());
        stem.put(kk().generateIDs(), v.isGenerateIDs());
        stem.put(kk().useTimestampsInIds(), v.isUseTimestampInIDs());
        stem.put(kk().allowCustomIDs(), v.isAllowCustomIDs());
        if(v.getIdHead() != null){
            stem.put(kk().idHead(), v.getIdHead().toString());
        }
        stem.put(kk().listUsers(), v.isListUsers());
        stem.put(kk().listUsersInOtherClients(), v.isListUsersInOtherClients());
        setNonNullStemValue(stem, kk().config(), v.getConfig().toString());
        setNonNullStemValue(stem, kk().issuer(), v.getIssuer());
        stem.put(kk().maxClients(), Long.valueOf(v.getMaxClients()));
        setNonNullStemValue(stem, kk().allowQDLCodeBlocks(), v.allowQDLCodeBlocks());

        setNonNullStemValue(stem, kk().voURI(), v.getVirtualOrganization().toString());
        setNonNullStemValue(stem, kk().vo(), v.getExternalVOName());
        return stem;
    }

}
