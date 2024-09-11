package org.oa4mp.client.loader;

import org.oa4mp.client.api.Asset;
import org.oa4mp.client.api.storage.AssetConverter;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenFactory;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import net.sf.json.JSONObject;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  2:42 PM
 */
public class OA2AssetConverter extends AssetConverter {

    public OA2AssetConverter(SerializationKeys keys, IdentifiableProvider<Asset> provider) {
        super(keys, provider);
    }

    OA2AssetSerializationKeys getASK() {
        return (OA2AssetSerializationKeys) keys;
    }

    @Override
    public Asset fromMap(ConversionMap<String, Object> map, Asset asset) {
        OA2Asset a = (OA2Asset) super.fromMap(map, asset);
        String rawCR = map.getString(getASK().certReq());
        if (rawCR != null) {
            MyPKCS10CertRequest certReq = CertUtil.fromStringToCertReq(rawCR);
            a.setCertReq(certReq);
        }
        if (map.containsKey(getASK().accessToken()) && map.get(getASK().accessToken()) != null) {
            // try the new way
            AccessTokenImpl accessToken;
            try {
                JSONObject json = JSONObject.fromObject(map.getString(getASK().accessToken()));
                accessToken = TokenFactory.createAT(json);
            } catch (Throwable t) {
                accessToken = new AccessTokenImpl(URI.create(map.getString(getASK().accessToken())));
            }
            a.setAccessToken(accessToken);
        }
        //String at = map.getString(getASK().accessToken());

        //if (at != null) a.setAccessToken(TokenFactory.createAT(at));
        if (map.containsKey(getASK().refreshToken()) && map.get(getASK().refreshToken()) != null) {
            RefreshTokenImpl refreshToken;
            try {
                JSONObject json = JSONObject.fromObject(map.getString(getASK().refreshToken()));
                refreshToken = TokenFactory.createRT(json);
            } catch (Throwable t) {
                refreshToken = new RefreshTokenImpl(URI.create(map.getString(getASK().refreshToken())));

            }
            a.setRefreshToken(refreshToken);
        }
        //  String rt = map.getString(getASK().refreshToken());
       /* if (rt != null) {
            a.setRefreshToken(TokenFactory.createRT(rt));
        }*/
        String state = map.getString(getASK().state());
        if (state != null) {
            a.setState(state);
        }
        a.setNonce(map.getString(getASK().nonce()));
        if (map.containsKey(getASK().issuedAt())) {
            a.setIssuedAt(map.getDate(getASK().issuedAt()));
        }
         // Unlink refresh and access tokens, this might also have been previously serialized
        // straight up as the JSON payload. In which case, the factory will make the right choice
        // and populate the token.
        if (map.containsKey(getASK().idToken()) && map.get(getASK().idToken()) != null) {
            String idt = map.getString(getASK().idToken());
            a.setIdToken(TokenFactory.createIDT(JSONObject.fromObject(idt)));
        }

        return a;
    }

    @Override
    public void toMap(Asset asset, ConversionMap<String, Object> map) {
        super.toMap(asset, map);
        OA2Asset a = (OA2Asset) super.fromMap(map, asset);
        if (a.getCertReq() != null) {
            map.put(getASK().certReq(), CertUtil.fromCertReqToString(asset.getCertReq()));
        }
        if (a.getAccessToken() != null) {
            map.put(getASK().accessToken(), a.getAccessToken().toJSON().toString());
        }
        //if (a.getAccessToken() != null) {map.put(getASK().accessToken(), a.getAccessToken().getToken());}
        if (a.getRefreshToken() != null) {
            map.put(getASK().refreshToken(), a.getRefreshToken().toJSON().toString());
/*
            map.put(getASK().refreshToken(), a.getRefreshToken().getToken());
            map.put(getASK().refreshLifetime(), a.getRefreshToken().getLifetime());
*/
        }
        if (a.getState() != null) {
            map.put(getASK().state(), a.getState());
        }
        map.put(getASK().nonce(), a.getNonce());
        if (a.getIdToken() != null) {
            map.put(getASK().idToken(), a.getIdToken().toJSON().toString());
        }
        if (a.getIssuedAt() != null) {
            map.put(getASK().issuedAt(), a.getIssuedAt());
        }

    }
}
