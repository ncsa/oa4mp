package org.oa4mp.server.api.storage.servlet;

import edu.uiuc.ncsa.myproxy.MPConnectionProvider;
import edu.uiuc.ncsa.myproxy.MyProxyConnectable;
import org.oa4mp.server.api.util.JGlobusUtil;
import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.MyX509Certificates;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.ConnectionException;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;

import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.LinkedList;

/**
 * This is the super class of the servlet that is supposed to retrieve a cert. This happens at different
 * times in different protocols. This will retrieve the cert and assumes that there is an {@link MyProxyConnectable}
 * that has been found and is cached. This will close the connection at the end of the request.
 * If the client should get a limited proxy, that will be done here as well.<br/>
 * Finally, if the DN from the cert is to be returned as the username in the final call to the service,
 * that will be set here.
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/14 at  11:30 AM
 */
public abstract class CRServlet extends MyProxyDelegationServlet {

    /**
     * Indirection call. If your extension to this class needs to do any
     * prep work before calling {@link #doCertRequest(edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction, String)}
     * put it here. And this should contain the actual call to that method. This is called in the authorization leg
     * and the getCert call. You should point this at the {@link #doCertRequest(ServiceTransaction, String)} method
     * here which does all the dirty work of tracking down the connection and getting the cert. So, depending on your
     * protocol you will have only one of two places where this is fully implemented.
     */
    abstract protected void doRealCertRequest(ServiceTransaction trans, String statusString) throws Throwable;

    /**
     * There are various requirements for transmitting the access token, so specific methods have to be used.
     *
     * @param request
     * @return
     */
    abstract protected AccessToken getAccessToken(HttpServletRequest request);

    protected void doCertRequest(ServiceTransaction trans,
                                 String statusString
    ) throws Throwable {
        if (!hasMPConnection(trans)) {
            throw new ConnectionException("Error: There is no currently active MyProxy connection.");
        }
        MyPKCS10CertRequest localCertRequest = trans.getCertReq();

        KeyPair keyPair = null;
        if (trans.getClient().isProxyLimited()) {
            info("3.b. starting proxy limited for " + trans.getClient().getIdentifier() + ". Generating keypair and cert request.");
            try {
                keyPair = getServiceEnvironment().getKeyPair();
                localCertRequest = CertUtil.createCertRequest(keyPair);
            } catch (GeneralSecurityException e) {
                error("3.b. " + e.getMessage());
                throw new GeneralException("Error: Could not create cert request:" + e.getMessage());
            }

        }
        LinkedList<X509Certificate> certs = getX509Certificates(trans, localCertRequest, statusString);
        debug("3.b. Got cert from server, count=" + certs.size());
        LinkedList<X509Certificate> certList = new LinkedList<>();
        // If it is a limited cert, sign it
        if (trans.getClient().isProxyLimited()) {
            info("3.b. Limited proxy for client " + trans.getClient().getIdentifier() + ", creating limited cert and signing it.");
            certList.addAll(certs);
            certList.addFirst(JGlobusUtil.createProxyCertificate(certs.getLast(),
                    keyPair.getPrivate(), trans.getCertReq().getPublicKey(),
                    (int) (trans.getLifetime() / 1000
                    )));
            certs = certList;
        }
        debug("3.b. Preparing to return cert chain of " + certs.size() + " to client.");
        MyX509Certificates myCerts = new MyX509Certificates(certs);
        trans.setProtectedAsset(myCerts);
        String userName = trans.getUsername();

        if (getServiceEnvironment().getAuthorizationServletConfig().isReturnDnAsUsername()) {
            if (myCerts.getX509Certificates().length > 0) {
                X500Principal x500Principal = myCerts.getX509Certificates()[0].getSubjectX500Principal();
                userName = x500Principal.getName();
                if (getServiceEnvironment().getAuthorizationServletConfig().isConvertDNToGlobusID()) {
                    userName = JGlobusUtil.toGlobusID(userName);
                }

                debug(statusString + ": USERNAME = " + userName);
            } else {
                userName = "no_certificates_found";
            }
            trans.setUsername(userName);
            info("3.c. Set username returned to client to first certificate's DN: " + userName);
        }

        trans.setUsername(userName); // Fixes OAUTH-102 username might not be set in some cases, so just reset it here.

        // Our response is a simple ok, since otherwise exceptions are thrown. No need to set this since that is the default.
        trans.setVerifier(MyProxyDelegationServlet.getServiceEnvironment().getTokenForge().getVerifier());
        getServiceEnvironment().getTransactionStore().save(trans);
        if (hasMPConnection(trans.getIdentifier())) {
            // It can happen (especially in cases of manual testing when there is considerable time between calls)
            // that the connection goes away. This prevents a bogus failure in that case.
            getMPConnection(trans.getIdentifier()).close();
        }
    }


    /**
     * Loops through the facade looking for the active connection and calls it.
     *
     * @param transaction
     * @param localCertRequest
     * @param statusString
     * @return
     */
    protected LinkedList<X509Certificate> getX509Certificates(ServiceTransaction transaction,
                                                              MyPKCS10CertRequest localCertRequest,
                                                              String statusString)  {

        MyProxyConnectable mpc = getMPConnection(transaction);
        mpc.setLifetime(transaction.getLifetime());
        LinkedList<X509Certificate> certs = mpc.getCerts(localCertRequest);

        if (certs.isEmpty()) {
            info(statusString + "Error: MyProxy service returned no certs.");
            throw new GeneralException("Error: MyProxy service returned no certs.");
        }

        info(statusString + "Got cert from MyProxy, issuing a limited proxy & storing it.");
        return certs;
    }

    /**
     * Returns a working MyProxy connection or it fails.
     *
     * @param identifier
     * @param userName
     * @param password
     * @return
     * @throws GeneralSecurityException
     */
    protected MyProxyConnectable createMPConnection(Identifier identifier,
                                                    String userName,
                                                    String password,
                                                    long lifetime) throws GeneralSecurityException {
        return createMPConnection(identifier, userName, password, lifetime, null); // no loa
    }

    protected MyProxyConnectable createMPConnection(Identifier identifier,
                                                    String userName,
                                                    String password,
                                                    long lifetime,
                                                    String loa) throws GeneralSecurityException {
        MPConnectionProvider facades = new MPConnectionProvider(getMyLogger(), MyProxyDelegationServlet.getServiceEnvironment().getMyProxyServices());
        MyProxyConnectable mpc = facades.findConnection(identifier, userName, password, loa, lifetime);
        DebugUtil.trace(this,mpc.toString());
        getMyproxyConnectionCache().add( mpc);
        return mpc;
    }


}
