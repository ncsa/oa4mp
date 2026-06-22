package org.oa4mp.server.api.storage.servlet;

import org.oa4mp.server.api.ServiceEnvironment;

import java.security.GeneralSecurityException;

import static org.oa4mp.server.api.OA4MPConfigTags.AUTHORIZATION_SERVLET_USE_MODE_PROXY;

public class AuthenticationUtil {
    static AuthenticationUtil authenticationUtil = null;

    public static boolean hasAuthenticationUtil() {
        return authenticationUtil != null;
    }

    public static AuthenticationUtil getInstance() {
        if (authenticationUtil == null) {
            authenticationUtil = new AuthenticationUtil();
        }
        return authenticationUtil;
    }

    public static void setInstance(AuthenticationUtil instance) {
        authenticationUtil = instance;
    }

    public void checkUser(ServiceEnvironment serviceEnvironment, String username, String password) throws GeneralSecurityException {
        // At this point in the basic servlet, there is no system for passwords.
        // This is because OA4MP has no native concept of managing users, it being
        // far outside of the OAuth spec.

        // authentication is done external to OA4MP, so this should not check the user.
        if(serviceEnvironment.getAuthorizationServletConfig().getUseMode().equals(AUTHORIZATION_SERVLET_USE_MODE_PROXY) && serviceEnvironment.getAuthorizationServletConfig().isLocalDFConsent()){
            return;
        }
        // Uncomment the next line when testing for release. This gives the test server a single
        // user with a password. Also check the wrong user/password fails.
        //
        //if(username.equals("me") && password.equals("12345678")) return;
        // If you were checking users and there  were a problem, you would do this:
        String message = "invalid login";
        throw new AbstractAuthenticationServlet.UserLoginException(message, username, password);
        // which would display the message as the retry message.
    }
}
