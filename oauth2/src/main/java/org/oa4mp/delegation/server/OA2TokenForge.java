package org.oa4mp.delegation.server;

import org.oa4mp.delegation.common.token.AccessToken;
import org.oa4mp.delegation.common.token.AuthorizationGrant;
import org.oa4mp.delegation.common.token.TokenForge;
import org.oa4mp.delegation.common.token.Verifier;
import org.oa4mp.delegation.server.server.AGRequest2;
import org.oa4mp.delegation.server.server.OIDCServiceTransactionInterface;
import org.oa4mp.delegation.server.server.RTIRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.MissingTokenException;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerRequest;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidTokenException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.IP2;
import org.oa4mp.delegation.common.token.impl.*;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Map;

import static org.oa4mp.delegation.common.token.impl.TokenUtils.b32DecodeToken;
import static org.oa4mp.delegation.common.token.impl.TokenUtils.isBase32;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/4/13 at  4:21 PM
 */
public class OA2TokenForge implements TokenForge {

    public AuthorizationGrantImpl createToken(AGRequest2 request) {
        return new AuthorizationGrantImpl(getAgIdProvider().get(request.getLifetime()));
    }

    public AccessTokenImpl createToken(ATRequest request) {
        return new AccessTokenImpl(metaCT(request, getAtIdProvider()));
    }

    public RefreshTokenImpl createToken(RTIRequest request) {
        return new RefreshTokenImpl(metaCT(request, getRefreshTokenProvider()));
    }

    /**
     * Does some grunt work of figuring out the lifetime then creates the URI. This is
     * <b>the</b> token and is used to create the various implementations.
     *
     * @param request
     * @param ip2
     * @return
     */
    protected URI metaCT(IssuerRequest request, IP2 ip2) {
        // meta create-token method.
        OIDCServiceTransactionInterface t = (OIDCServiceTransactionInterface) request.getTransaction();
        long lifetime = -1L;
        //long lifetime = t.getAuthzGrantLifetime();
        switch (request.getType()) {
            case IssuerRequest.AG_TYPE:
                lifetime = t.getAuthzGrantLifetime();
                break;
            case IssuerRequest.AT_TYPE:
                lifetime = t.getAccessTokenLifetime();
                break;
            case IssuerRequest.RT_TYPE:
                lifetime = t.getRefreshTokenLifetime();
                break;
            default:
                throw new NotImplementedException("Lifetime for request of type " + request.getClass().getSimpleName() + " not implemented.");
        }
        return ip2.get(lifetime);
    }

    public OA2TokenForge(String server) {
        this.server = server;
        // setup();
    }

    /**
     * This and similarly named methods are provided so you can override the specific path components and enforce
     * your own semantics on the tokens. Note that these are called once  and are immutable
     * after that. If you need something really exotic you should override the setup() method.
     *
     * @return
     */
    protected String authzGrant(String... x) {
        if (1 == x.length) authzGrant = x[0];
        return authzGrant;
    }

    protected String accessToken(String... x) {
        if (1 == x.length) accessToken = x[0];
        return accessToken;
    }


    protected String refreshToken(String... x) {
        if (1 == x.length) refreshToken = x[0];
        return refreshToken;
    }

    protected String asset(String... x) {
        if (1 == x.length) asset = x[0];
        return asset;
    }

    protected String userInfo(String... x) {
        if (1 == x.length) userInfo = x[0];
        return userInfo;
    }

    protected String verifierToken(String... x) {
        if (1 == x.length) verifierToken = x[0];
        return verifierToken;
    }

    protected String idToken(String... x) {
        if (1 == x.length) idToken = x[0];
        return idToken;
    }

    public String getServer() {
        return server;
    }

    URI serverURI = null;

    protected URI getServerURI() {
        if (serverURI == null) {
            serverURI = URI.create(getServer());
        }
        return serverURI;
    }

    String server;
    public String authzGrant = "authzGrant";
    public String accessToken = "accessToken";
    public String refreshToken = "refreshToken";
    public String verifierToken = "verifierToken";
    public String idToken = "idToken";
    public String asset = "asset";
    public String userInfo = "userInfo";

    @Override
    public AccessToken getAccessToken(Map<String, String> parameters) {
        String tokenVal = parameters.get(OA2Constants.ACCESS_TOKEN);
        if (tokenVal != null) {
            //return tokenVal;

            return new AccessTokenImpl(URI.create(tokenVal));
        }
        String authCode = parameters.get(OA2Constants.AUTHORIZATION_CODE);
        if (authCode == null) {
            throw new GeneralException(" missing authorization code");
        }
        return getAccessToken(authCode);
    }

    // These are used in the token introspection endpoint.
    public static final int TYPE_AUTH_GRANT = 1;
    public static final int TYPE_ACCESS_TOKEN = 10;
    public static final int TYPE_REFRESH_TOKEN = 100;
    public static final int TYPE_ID_TOKEN = 200;
    public static final int TYPE_UNKNOWN = 0;


    /**
     * Takes a token (as a string) and returns a human-readable type of token.
     * This is intended to be used in, e.g., logging applications.
     * @param x
     * @return
     */
    public String getStringType(String x) {
        switch (getType(x)){
            case TYPE_ACCESS_TOKEN:
                return "access token";
            case TYPE_REFRESH_TOKEN:
                return "refresh token";
            case TYPE_AUTH_GRANT:
                return "authz grant";
            case TYPE_ID_TOKEN:
                return "id token";
            default:
            case TYPE_UNKNOWN:
                return "unknown token";
        }
    }
    public int getType(String x) {
        String s = getServer();
        if (!s.endsWith("/")) {
            s = s + "/"; // just making sure
        }
        if (!x.startsWith(s)) {
            return TYPE_UNKNOWN;
        }
        // be sure it is conformable to the spec
        try {
            URI uri = URI.create(x);
        } catch (Throwable t) {
            return TYPE_UNKNOWN;

        }
        x = x.substring(s.length()); //whack off server, next component tells us what it is.
        if (x.startsWith(accessToken() + "/")) return TYPE_ACCESS_TOKEN;
        if (x.startsWith(authzGrant() + "/")) return TYPE_AUTH_GRANT;
        if (x.startsWith(refreshToken() + "/")) return TYPE_REFRESH_TOKEN;
        if (x.startsWith(idToken() + "/")) return TYPE_ID_TOKEN;
        return TYPE_UNKNOWN; // booby prize.

    }

    @Override
    public AuthorizationGrant getAuthorizationGrant(Map<String, String> parameters) {
        String token = parameters.get(OA2Constants.AUTHORIZATION_CODE);
        if (token == null) {
            throw new MissingTokenException(" the authorization grant token is missing.");
        }
        return getAuthorizationGrant(token);
    }


    @Override
    public AuthorizationGrant getAuthorizationGrant(HttpServletRequest request) {
        try {
            return getAuthorizationGrant(OA2Utilities.getParameters(request));
        } catch (Exception e) {
            throw new GeneralException(" could not create the authorization grant", e);
        }
    }

    @Override
    public AuthorizationGrant getAuthorizationGrant(String... tokens) {
        switch (tokens.length) {
            case 0:
                return new AuthorizationGrantImpl(getAgIdProvider().get().getUri());

            default:
                if(tokens[0] == null){
                    return new AuthorizationGrantImpl(null);
                }
                if(isBase32(tokens[0])){
                    return new AuthorizationGrantImpl(tokens[0] == null ? null : URI.create(b32DecodeToken(tokens[0])));
                } else {
                    return new AuthorizationGrantImpl(URI.create(tokens[0]));
                }
        }
    }


    public TokenImpl getIDToken(String... tokens) {
        switch (tokens.length) {
            case 0:
                return new TokenImpl(getIDTokenProvider().get().getUri());

            default:
                return new TokenImpl(tokens[0] == null ? null : URI.create(tokens[0]));
        }
    }

    @Override
    public AccessToken getAccessToken(HttpServletRequest request) {
        try {
            return getAccessToken(OA2Utilities.getParameters(request));
        } catch (Exception e) {
            throw new GeneralException("Could not create a token", e);
        }
    }

    public IP2<Identifier> getAgIdProvider() {
        if (agIdProvider == null) {
            //agIdProvider = new IdentifierProvider<Identifier>(URI.create(getServer()), authzGrant(), true) {
            agIdProvider = new IP2<Identifier>(URI.create(getServer()), authzGrant(), true) {
            };
        }
        return agIdProvider;
    }

  /*  public void setAgIdProvider(IdentifierProvider<Identifier> agIdProvider) {
        this.agIdProvider = agIdProvider;
    }*/

    public IP2<Identifier> getAtIdProvider() {
        if (atIdProvider == null) {
            //atIdProvider = new IdentifierProvider<Identifier>(URI.create(getServer()), accessToken(), true) {
            atIdProvider = new IP2<Identifier>(URI.create(getServer()), accessToken(), true) {
            };
        }
        return atIdProvider;
    }

  /*  public void setAtIdProvider(IdentifierProvider<Identifier> atIdProvider) {
        this.atIdProvider = atIdProvider;
    }*/

    public IP2<Identifier> getRefreshTokenProvider() {
        if (refreshTokenProvider == null) {
            //   refreshTokenProvider = new IdentifierProvider<Identifier>(URI.create(getServer()), refreshToken(), true) {
            refreshTokenProvider = new IP2<Identifier>(URI.create(getServer()), refreshToken(), true) {
            };
        }
        return refreshTokenProvider;
    }

/*    public void setRefreshTokenProvider(IdentifierProvider<Identifier> refreshTokenProvider) {
        this.refreshTokenProvider = refreshTokenProvider;
    }*/

    public IP2<Identifier> getIDTokenProvider() {
        if (idTokenprovider == null) {
          /*  idTokenprovider = new IdentifierProvider<edu.uiuc.ncsa.security.core.Identifier>(URI.create(getServer()),
                    idToken(), true) {*/
            idTokenprovider = new IP2<edu.uiuc.ncsa.security.core.Identifier>(URI.create(getServer()),
                    idToken(), true) {
            };
        }
        return idTokenprovider;
    }


    public IP2<Identifier> getVerifierTokenProvider() {
        if (verifierTokenProvider == null) {
            //verifierTokenProvider = new IdentifierProvider<Identifier>(URI.create(getServer()), verifierToken(), true) {
            verifierTokenProvider = new IP2(URI.create(getServer()), verifierToken(), true) {
            };
        }
        return verifierTokenProvider;
    }

/*
    public void setVerifierTokenProvider(IdentifierProvider<Identifier> verifierTokenProvider) {
        this.verifierTokenProvider = verifierTokenProvider;
    }
*/

    /*
       Note that our specification dictates that grants, verifiers  and access tokens conform to the
       semantics of identifiers. We have to provide these.
        */
    IP2<Identifier> atIdProvider;
    IP2<Identifier> agIdProvider;
    IP2<Identifier> refreshTokenProvider;
    IP2<Identifier> verifierTokenProvider;
    IP2<Identifier> idTokenprovider = null;

    protected URI getURI(String token) {
        try {
            return URI.create(token);
        } catch (Throwable t) {
            throw new InvalidTokenException("Invalid token \"" + token + "\"", t);
        }
    }

    public RefreshTokenImpl getRefreshToken(String... tokens) {
        switch (tokens.length) {
            case 0:
                return new RefreshTokenImpl(getRefreshTokenProvider().get().getUri());

            default:
                return new RefreshTokenImpl(tokens[0] == null ? null : URI.create(tokens[0]));
        }
    }


    @Override
    public AccessTokenImpl getAccessToken(String... tokens) {
        switch (tokens.length) {
            case 0:
                return new AccessTokenImpl(getAtIdProvider().get().getUri());

            default:
                return new AccessTokenImpl(URI.create(tokens[0]));
        }
    }

    //TODO Resolve conflict between this and legacy classes (e.g. AbstractAuthorizationServlet)
    @Override
    public Verifier getVerifier(Map<String, String> parameters) {
        //throw new UnsupportedOperationException("Error: Verifiers are not used in OAuth2");
        return null;
    }

    @Override
    public Verifier getVerifier(HttpServletRequest request) {
        //throw new UnsupportedOperationException("Error: Verifiers are not used in OAuth2");
        return null;
    }

    @Override
    public Verifier getVerifier(String... tokens) {
        switch (tokens.length) {
            case 0:
                return new VerifierImpl(getVerifierTokenProvider().get().getUri());

            default:
                return new VerifierImpl(URI.create(tokens[0]));
        }

    }
}
