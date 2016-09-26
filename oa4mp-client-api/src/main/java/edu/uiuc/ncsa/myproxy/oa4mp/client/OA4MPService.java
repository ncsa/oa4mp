package edu.uiuc.ncsa.myproxy.oa4mp.client;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import edu.uiuc.ncsa.security.util.pkcs.MyPKCS10CertRequest;
import org.apache.commons.codec.binary.Base64;

import java.security.KeyPair;
import java.util.Map;

import static edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment.CALLBACK_URI_KEY;

/**
 * The OAuth for MyProxy service. Note that the {@link ClientEnvironment} is queried for its properties
 * for each call, so that changes on a per request basis will be performed.
 * <p>Created by Jeff Gaynor<br>
 * on May 16, 2011 at  3:27:16 PM
 */
public class OA4MPService extends AbstractOA4MPService {


    /**
     * Basic constructor for this service.
     *
     * @param environment
     */
    public OA4MPService(ClientEnvironment environment) {
        super(environment);
    }


    @Override
    public void preRequestCert(Asset asset, Map additionalParameters) {
        KeyPair keyPair = getNextKeyPair();
        MyPKCS10CertRequest certReq = null;
        try {
            certReq = CertUtil.createCertRequest(keyPair);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) {
                throw (RuntimeException) e;
            }
            throw new GeneralException("Could not create cert request", e);
        }
        asset.setPrivateKey(keyPair.getPrivate());
        asset.setCertReq(certReq);

        additionalParameters.put(ClientEnvironment.CERT_REQUEST_KEY, Base64.encodeBase64String(asset.getCertReq().getEncoded()));
        //additionalParameters.put(ClientEnvironment.CERT_REQUEST_KEY, "Mairzy doates and does eat stoats.");
        if (!additionalParameters.containsKey(getEnvironment().getConstants().get(CALLBACK_URI_KEY))) {
            additionalParameters.put(getEnvironment().getConstants().get(CALLBACK_URI_KEY), getEnvironment().getCallback().toString());
        }
        if (0 <= getEnvironment().getCertLifetime()) {
            additionalParameters.put(ClientEnvironment.CERT_LIFETIME_KEY, getEnvironment().getCertLifetime());
        }
    }

    @Override
    public void postRequestCert(Asset asset, OA4MPResponse oa4MPResponse) {

    }

    @Override
    public void postGetCert(Asset asset, AssetResponse assetResponse) {

    }

    @Override
    public void preGetCert(Asset asset, Map parameters) {

    }
}
