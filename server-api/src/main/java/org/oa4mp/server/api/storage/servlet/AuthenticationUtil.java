package org.oa4mp.server.api.storage.servlet;

import org.oa4mp.server.api.ServiceEnvironment;

import java.security.GeneralSecurityException;

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

        // If you were checking users and there  were a problem, you would do this:
        String message = "invalid login";
        throw new AbstractAuthenticationServlet.UserLoginException(message, username, password);
        // which would display the message as the retry message.
    }
}
