package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPResponse;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPService;
import junit.framework.TestCase;
import org.junit.Test;

import java.net.URI;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/23/12 at  5:04 PM
 */
public class ClientParameterTest extends TestCase {
    public class OA4MPService2 extends OA4MPService{
        public OA4MPService2(ClientEnvironment environment) {
            super(environment);
        }

        @Override
        public OA4MPResponse requestCert(Map additionalParameters) {
            ClientEnvironment2 ce = new ClientEnvironment2(getEnvironment(), null);
            return super.requestCert(additionalParameters);
        }
    }
       public class ClientEnvironment2 extends ClientEnvironment {
        public ClientEnvironment2(ClientEnvironment c, URI customCallback){
            super(c.getAccessTokenUri(),
                    c.getAuthorizationUri(),
                    customCallback,
                    c.getCertLifetime(),
                    c.getClientId(),
                    c.getDelegationService(),
                    c.getInitializeUri(),
                    c.getPrivateKey(),
                    c.getPublicKey(),
                    c.getResourceServerUri(),
                    c.getTokenForge(),
                    null,
                    true,
                     null,null,null// debug mode is to show redirect page.
                    );
        }
    }

    @Test

    public void testCallback() throws Exception{

    }
}
