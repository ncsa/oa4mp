package org.oa4mp.delegation.server.client;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.security.servlet.ServiceClient;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONObject;
import org.oa4mp.delegation.client.request.RFC7523Request;
import org.oa4mp.delegation.client.request.RFC7523Response;
import org.oa4mp.delegation.common.storage.clients.BaseClient;
import org.oa4mp.delegation.common.storage.clients.BaseClientConverter;
import org.oa4mp.delegation.common.storage.clients.BaseClientKeys;
import org.oa4mp.delegation.common.storage.clients.ClientProvider;
import org.oa4mp.delegation.server.server.RFC7523Constants;

import java.net.URI;

import static org.oa4mp.delegation.server.OA2Constants.ID_TOKEN;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/6/23 at  3:11 PM
 */
public class RFC7523Server extends TokenAwareServer implements RFC7523Constants {
    public RFC7523Server(ServiceClient serviceClient, URI issuer, String wellKnown, boolean oidcEnabled) {
        super(serviceClient, issuer, wellKnown, oidcEnabled);
    }

    public RFC7523Response processRFC7523Request(RFC7523Request request) {
        String response;
        if (request.getParameters().containsKey(ADMIN_CLIENT)) {
            // We need an ID provider to create the class, but are not creating new admin clients,
            // so this is just a placeholder.
            IdentifierProvider<Identifier> idp = new IdentifierProvider<Identifier>("admins") {
            };
            ClientProvider clientProvider = new ClientProvider(idp);
            BaseClientKeys baseClientKeys = new BaseClientKeys();
            baseClientKeys.identifier("admin_id");
            baseClientKeys.secret("secret");
            BaseClientConverter bcc = new BaseClientConverter(baseClientKeys,
                    clientProvider);
            {
                JSONObject wrapper = new JSONObject();
                wrapper.put(bcc.getJSONComponentName(), request.getParameters().get(ADMIN_CLIENT));
                BaseClient adminClient = bcc.fromJSON(wrapper);
                String adminKID = (String) request.getParameters().get(ADMIN_KID);
                // clean up so these don't get sent
                request.getParameters().remove(ADMIN_CLIENT);
                request.getParameters().remove(ADMIN_KID);
                JSONWebKey key ;
                if (adminClient.hasJWKSURI()) {
                    String rawKeys = serviceClient.doGet(adminClient.getJwksURI().toString(), null);
                    JSONWebKeys keys = null;
                    try {
                        JWKUtil2 jwkUtil21 = new JWKUtil2();
                        keys = jwkUtil21.fromJSON(rawKeys);
                        key = keys.get(adminKID);
                    } catch (Throwable e) {
                        throw new GeneralException("could not get keys", e);
                    }
                } else {
                     key = adminClient.getJWKS().get(adminKID);
                }
                response = RFC7523Utils.doInitFlowTokenRequest(getServiceClient(),
                        adminClient,
                        key,
                        request.getClient(),
                        getTokenEndpoint(),
                        request.getParameters());

            }
        } else {
            response = RFC7523Utils.doTokenRequest(getServiceClient(),
                    request.getClient(),
                    getTokenEndpoint(),
                    request.getKeyID(),
                    request.getParameters());
        }
        RFC7523Response rfc7523Response = new RFC7523Response();
        rfc7523Response.setResponse(JSONObject.fromObject(response)); // contains access token and refresh token.

        // This checks the ID token and verifies it. Use this, not the raw ID token in the response.
        // Not all clients return them, e.g. pure OAuth 2 clients.
        if (rfc7523Response.getResponse().containsKey(ID_TOKEN)) {
            rfc7523Response.setIdToken(getAndCheckIDToken(rfc7523Response.getResponse(), request));
        }
        return rfc7523Response;
    }
}
