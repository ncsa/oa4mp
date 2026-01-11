package org.oa4mp.server.qdl.storage;

import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import net.sf.json.JSONObject;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientKeys;
import org.qdl_lang.variables.QDLStem;

import java.net.URI;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/20 at  6:21 AM
 */
public class AdminClientStemMC<V extends AdminClient> extends BaseClientStemMC<V> {
    public AdminClientStemMC(MapConverter<V> mapConverter) {
        super(mapConverter);
    }

    AdminClientKeys kk() {
        return (AdminClientKeys) keys;
    }

    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        /* Admin client attributes

           String allowCustomIDs = "allow_custom_ids";
           String allowQDL = "allow_qdl";
           String allowQDLCodeBlocks = "allow_qdl_code_blocks";
           String config = "config";
           String generateIDs = "generate_ids";
           String idStart = "id_start";
           String initializeFlows = "initialize_flows";
           String issuer = "issuer";
           String listUsers = "list_users";
           String listUsersInOtherClients = "list_users_other_clients";
           String maxClients = "max_clients";
           String notifyOnNewClientCreate="new_client_notify";
           String useTimestampsInIDs = "use_timestamps_in_ids";
           String vo="vo";
           String voURI="vo_uri";

           */
        // Attributes specific to admin clients
        if (stem.containsKey(kk().allowCustomIDs())) {v.setAllowCustomIDs(stem.getBoolean(kk().allowCustomIDs()));}
        if (stem.containsKey(kk().allowQDL())) {v.setAllowQDL(stem.getBoolean(kk().allowQDL()));}
        if (stem.containsKey(kk().allowQDLCodeBlocks())) {v.setAllowQDLCodeBlocks(stem.getBoolean(kk().allowQDLCodeBlocks()));}
        if (isStringKeyOK(stem, kk().config())) {v.setConfig(JSONObject.fromObject(stem.getString(kk().config())));}
        if (stem.containsKey(kk().generateIDs())) {v.setGenerateIDs(stem.getBoolean(kk().generateIDs()));}
        if (stem.containsKey(kk().idHead())) {v.setIdHead(URI.create(stem.getString(kk().idHead())));}
        if (stem.containsKey(kk().initializeFlows())) {v.setInitializeFlows(stem.getBoolean(kk().initializeFlows()));}
        if (isStringKeyOK(stem, kk().issuer())) {v.setIssuer(stem.getString(kk().issuer()));}
        if (stem.containsKey(kk().listUsers())) {v.setListUsers(stem.getBoolean(kk().listUsers()));}
        if (stem.containsKey(kk().listUsersInOtherClients())) {v.setListUsersInOtherClients(stem.getBoolean(kk().listUsersInOtherClients()));}
        if (stem.containsKey(kk().maxClients())) {v.setMaxClients(stem.getLong(kk().maxClients()).intValue());}
        if (stem.containsKey(kk().notifyOnNewClientCreate())) {v.setNotifyOnNewClientCreate(stem.getBoolean(kk().notifyOnNewClientCreate()));}
        if (stem.containsKey(kk().useTimestampsInIds())) {v.setUseTimestampInIDs(stem.getBoolean(kk().useTimestampsInIds()));}
        if (isStringKeyOK(stem, kk().vo())) {v.setVirtualIssuer(BasicIdentifier.newID(stem.getString(kk().voURI())));}
        if (isStringKeyOK(stem, kk().voURI())) {v.setExternalVIName(stem.getString(kk().voURI()));}

        return v;
    }


    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);

        put(stem, kk().allowCustomIDs(), v.isAllowCustomIDs());
        put(stem, kk().allowQDL(), v.isAllowQDL());
        setNonNullStemValue(stem, kk().allowQDLCodeBlocks(), v.allowQDLCodeBlocks());
        if(v.getConfig()!=null){
            QDLStem ss = new QDLStem();
            ss.fromJSON(v.getConfig());
            put(stem, kk().config(), ss);
        }

        put(stem, kk().generateIDs(), v.isGenerateIDs());
        if (v.getIdHead() != null) {put(stem, kk().idHead(), v.getIdHead().toString());}
        put(stem, kk().initializeFlows(), v.canInitializeFlows());
        setNonNullStemValue(stem, kk().issuer(), v.getIssuer());
        put(stem, kk().listUsers(), v.isListUsers());
        put(stem, kk().listUsersInOtherClients(), v.isListUsersInOtherClients());
        put(stem, kk().maxClients(), Long.valueOf(v.getMaxClients()));
        put(stem, kk().notifyOnNewClientCreate(), v.isNotifyOnNewClientCreate());
        put(stem, kk().useTimestampsInIds(), v.isUseTimestampInIDs());
        setNonNullStemValue(stem, kk().vo(), v.getExternalVIName());
        if (v.getVirtualIssuer() != null) {
            setNonNullStemValue(stem, kk().voURI(), v.getVirtualIssuer().toString());
        }

        return stem;
    }

}
