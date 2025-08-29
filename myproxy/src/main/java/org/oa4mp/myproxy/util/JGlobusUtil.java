package org.oa4mp.myproxy.util;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import org.globus.gsi.GSIConstants;
import org.globus.gsi.X509ExtensionSet;
import org.globus.gsi.bc.BouncyCastleCertProcessingFactory;
import org.globus.gsi.bc.BouncyCastleUtil;
import org.globus.gsi.proxy.ext.ProxyCertInfo;
import org.globus.gsi.proxy.ext.ProxyCertInfoExtension;
import org.globus.gsi.proxy.ext.ProxyPolicy;
import org.globus.gsi.util.CertificateUtil;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

/**
 * A class that centralizes JGlobus calls.
 * <p>Created by Jeff Gaynor<br>
 * on 10/17/13 at  1:03 PM
 */
public class JGlobusUtil {
    public static String getUsername(X509Certificate cert) {
        return BouncyCastleUtil.getIdentity(cert);
    }

    public static X509Certificate createProxyCertificate(X509Certificate baseCert,
                                                         PrivateKey generatedPrivateKey,
                                                         PublicKey publicKey,
                                                         int certLifetimeInSeconds
    ) {
        // Sign a cert req from OAuth client using a cert obtained from MyProxy server
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        ProxyPolicy policy = new ProxyPolicy(ProxyPolicy.LIMITED);
        ProxyCertInfo proxyCertInfo = new ProxyCertInfo(policy);
        X509ExtensionSet extSet = new X509ExtensionSet();
        extSet.add(new ProxyCertInfoExtension(proxyCertInfo));

        BouncyCastleCertProcessingFactory factory =
                BouncyCastleCertProcessingFactory.getDefault();
        try {
            // add the cert afterwards so there is no issue with modifying the list early.
            X509Certificate x = factory.createProxyCertificate(baseCert,
                    generatedPrivateKey,
                    publicKey,
                    certLifetimeInSeconds,
                    GSIConstants.CertificateType.GSI_4_LIMITED_PROXY,
                    extSet,
                    null);
            return x;
        } catch (GeneralSecurityException e) {
            String errMsg = "3.c. Error: signing a limited proxy credential: " + e.getMessage();
            throw new GeneralException(errMsg, e); // throw it.
        }
    }

    public static String toGlobusID(String dn) {
        return CertificateUtil.toGlobusID(dn);
    }
}
