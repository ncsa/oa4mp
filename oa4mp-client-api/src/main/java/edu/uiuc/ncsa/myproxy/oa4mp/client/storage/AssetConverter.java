package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.KeyUtil;

import java.security.cert.CertificateException;

/**
 * A serializer that converts {@link Asset}s to/from key/value pairs. This is used by
 * every {@link AssetStore} and provides a consistent mechanism for these conversions.
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/13 at  3:39 PM
 */
public class AssetConverter extends MapConverter<Asset> {
    public AssetConverter(SerializationKeys keys, IdentifiableProvider<Asset> provider) {
        super(keys, provider);
    }

    protected AssetSerializationKeys getAR() {
        return (AssetSerializationKeys) keys;
    }

    @Override
    public Asset fromMap(ConversionMap<String, Object> map, Asset asset) {
        super.fromMap(map, asset);
        asset.setUsername(map.getString(getAR().username()));
        try {
            String rawCert = map.getString(getAR().certificates());
            if (rawCert != null && 0 < rawCert.length()) {
                asset.setCertificates(CertUtil.fromX509PEM(rawCert));
            }
        } catch (CertificateException e) {
            throw new GeneralException("Error: could not create certificate", e);
        }
        String temp = map.getString(getAR().privateKey());
        if(temp != null){
            asset.setPrivateKey(KeyUtil.fromPKCS8PEM(temp));
        }

        asset.setRedirect(map.getURI(getAR().redirect()));
        asset.setCreationTime(map.getDate(getAR().creationTime()));
        asset.setToken(map.getIdentifier(getAR().token()));
        String rawCertReq = map.getString(getAR().certReq());
        if(rawCertReq != null){
            asset.setCertReq(CertUtil.fromStringToCertReq(rawCertReq));
        }
        return asset;
    }

    @Override
    public void toMap(Asset asset, ConversionMap<String, Object> map) {
        super.toMap(asset, map);
        if (asset.getPrivateKey() != null) {
            map.put(getAR().privateKey(), KeyUtil.toPKCS8PEM(asset.getPrivateKey()));
        }
        if(asset.getRedirect() != null){
            map.put(getAR().redirect(), asset.getRedirect().toString());
        }
        if(asset.getCertificates()!= null){
               map.put(getAR().certificates(), CertUtil.toPEM(asset.getCertificates()));
        }
        if(asset.getUsername() != null && 0 < asset.getUsername().length()){
            map.put(getAR().username(), asset.getUsername());
        }
        if(asset.getCreationTime() != null){
            map.put(getAR().creationTime(), asset.getCreationTime());
        }
        if(asset.getCertReq() != null){
            map.put(getAR().certReq(), CertUtil.fromCertReqToString(asset.getCertReq()));
        }
        if(asset.getToken() != null){
            map.put(getAR().token(), asset.getToken());
        }
    }

}
