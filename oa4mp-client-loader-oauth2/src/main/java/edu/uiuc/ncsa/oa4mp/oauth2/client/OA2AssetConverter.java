package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RefreshTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.server.OA2Claims;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;

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
        String at = map.getString(getASK().accessToken());
        if (at != null) a.setAccessToken(new AccessTokenImpl(URI.create(at)));
        String rt = map.getString(getASK().refreshToken());
        if (rt != null) {
            RefreshToken refreshToken = new OA2RefreshTokenImpl(URI.create(rt));
            refreshToken.setExpiresIn(map.getLong(getASK().refreshLifetime()));
            a.setRefreshToken(refreshToken);
        }
        String state = map.getString(getASK().state());
        if (state != null) {
            a.setState(state);
        }
        a.setNonce(map.getString(getASK().nonce()));
        if (map.containsKey(OA2Claims.ISSUED_AT)) {
            a.setIssuedAt(map.getDate(OA2Claims.ISSUED_AT));
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
        if (a.getAccessToken() != null) map.put(getASK().accessToken(), a.getAccessToken().getToken());
        if (a.getRefreshToken() != null) {
            map.put(getASK().refreshToken(), a.getRefreshToken().getToken());
            map.put(getASK().refreshLifetime(), a.getRefreshToken().getExpiresIn());
        }
        if (a.getState() != null) {
            map.put(getASK().state(), a.getState());
        }
        map.put(getASK().nonce(), a.getNonce());
        if (a.getIssuedAt() != null) {
            map.put(OA2Claims.ISSUED_AT, a.getIssuedAt());
        }
    }
}
