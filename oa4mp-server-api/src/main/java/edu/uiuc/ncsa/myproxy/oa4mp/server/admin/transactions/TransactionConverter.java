package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions;

import edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPServiceTransaction;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.server.storage.support.ServiceTransactionConverter;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.TokenForge;
import edu.uiuc.ncsa.security.storage.data.ConversionMap;
import edu.uiuc.ncsa.security.storage.data.SerializationKeys;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import static edu.uiuc.ncsa.security.util.pkcs.CertUtil.fromPEM;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/16/12 at  12:16 PM
 */
public class TransactionConverter<V extends OA4MPServiceTransaction> extends ServiceTransactionConverter<V> {
    public TransactionConverter(IdentifiableProvider<V> identifiableProvider,
                                TokenForge tokenForge,
                                ClientStore<? extends Client> cs
    ) {
        this(new DSTransactionKeys(), identifiableProvider, tokenForge, cs);

    }


    public TransactionConverter(SerializationKeys keys,
                                IdentifiableProvider<V> identifiableProvider,
                                TokenForge tokenForge,
                                ClientStore<? extends Client> cs
    ) {
        super(keys, identifiableProvider, tokenForge);
        this.clientStore = cs;

    }

    ClientStore<? extends Client> clientStore;


    protected DSTransactionKeys getDSTK() {
        return (DSTransactionKeys) getSTK();
    }

    @Override
    public V fromMap(ConversionMap<String, Object> map, V v) {
        V t = super.fromMap(map, v);
        String CertReqString = map.getString(getDSTK().certReq());
        if (CertReqString != null && 0 < CertReqString.length()) t.setCertReq(CertUtil.fromStringToCertReq(CertReqString));
        String y = map.getString(getDSTK().cert());
        if (y != null && 0 < y.length()) {
            try {
                ByteArrayInputStream baos = new ByteArrayInputStream(y.getBytes("UTF-8"));
                MyX509Certificates myCert = new MyX509Certificates(fromPEM(baos));
                t.setProtectedAsset(myCert);
            } catch (CertificateException e) {
                throw new GeneralException("Error decoding certificate", e);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }

        Identifier clientKey = BasicIdentifier.newID(map.getString(getDSTK().clientKey()));
        if (clientKey != null) {
            t.setClient(clientStore.get(clientKey));
        }
        String uName = map.getString(getDSTK().username());
        if (uName != null) {
            t.setUsername(uName);
        }
        String myproxyUsername = map.getString(getDSTK().myproxyUsername());
        if(myproxyUsername != null){
            t.setMyproxyUsername(myproxyUsername);
        }
        return t;
    }

    @Override
    public void toMap(V t, ConversionMap<String, Object> map) {
        super.toMap(t, map);
        if (t.getCertReq() == null) {
            map.put(getDSTK().certReq(), null);
        } else {
            map.put(getDSTK().certReq(), CertUtil.fromCertReqToString(t.getCertReq()));
        }
        MyX509Certificates myCert = (MyX509Certificates) t.getProtectedAsset();
        if (myCert == null || myCert.getX509Certificates() == null || myCert.getX509Certificates().length == 0) {
            map.put(getDSTK().cert(), null);
        } else {
            try {
                map.put(getDSTK().cert(), myCert.getX509CertificatesPEM());
            } catch (CertificateEncodingException e) {
                throw new GeneralException("Error: could not encode certificate", e);
            }
        }
        if (t.getClient() == null) {
            map.put(getDSTK().clientKey(), null);
        } else {
            map.put(getDSTK().clientKey(), t.getClient().getIdentifier());
        }
        if (t.getUsername() == null) {
            map.put(getDSTK().username(), null);
        } else {
            map.put(getDSTK().username(), t.getUsername());
        }
        if(t.getMyproxyUsername() == null){
            map.put(getDSTK().myproxyUsername(), null);
        }else{
            map.put(getDSTK().myproxyUsername(), t.getMyproxyUsername());
        }
    }
}
