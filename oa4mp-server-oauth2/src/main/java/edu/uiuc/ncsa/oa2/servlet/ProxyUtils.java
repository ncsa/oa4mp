package edu.uiuc.ncsa.oa2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RFC8628Store;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AbstractAuthorizationServlet;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.AuthorizationServletConfig;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CLCCommands;
import edu.uiuc.ncsa.myproxy.oauth2.tools.OA2CommandLineClient;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static edu.uiuc.ncsa.oa2.servlet.OA2AuthorizationServer.scopesToString;

/**
 * Class with shared proxy utilities
 * <p>Created by Jeff Gaynor<br>
 * on 3/4/22 at  4:55 PM
 */
public class ProxyUtils {

    protected static void doProxy(OA2SE oa2SE, RFC8628AuthorizationServer.PendingState pendingState) throws Throwable {
        RFC8628Store<? extends OA2ServiceTransaction> rfc8628Store = (RFC8628Store) oa2SE.getTransactionStore();
        OA2ServiceTransaction t = rfc8628Store.getByUserCode("");
        doProxy(oa2SE, t, pendingState.getResponse());
    }
    protected static void doProxy(OA2SE oa2SE, AbstractAuthorizationServlet.AuthorizedState state) throws Throwable {
        OA2ServiceTransaction t = (OA2ServiceTransaction) state.getTransaction();
        doProxy(oa2SE, t, state.getResponse());
    }
    protected static void doProxy(OA2SE oa2SE, OA2ServiceTransaction t, HttpServletResponse response) throws Throwable {
        AuthorizationServletConfig asc = oa2SE.getAuthorizationServletConfig();
        OA2CLCCommands clcCommands = new OA2CLCCommands(true, oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        // Construct a dummy argument to load the client configuration. Calling load() means the first argument has been
        // processed to locate the method (via introspection) and is ignored in the method.
        clcCommands.load(new InputLine("dummy " + asc.getCfgName() + "  " + asc.getCfgFile()));
        AbstractAuthorizationServlet.MyHttpServletResponseWrapper wrapper = new AbstractAuthorizationServlet.MyHttpServletResponseWrapper(response);
        // set the specific scopes.
        clcCommands.set_param(new InputLine("set_param -a scope \"" + scopesToString(t) + "\""));
        Identifier identifier = BasicIdentifier.randomID();
        String id = Base64.getEncoder().encodeToString(identifier.toString().getBytes(StandardCharsets.UTF_8));
        t.setProxyId(identifier.toString());
        t.setAuthGrantValid(true);
        clcCommands.set_param(new InputLine("set_param -a state " + id));
        clcCommands.uri(new InputLine("uri")); // side effect is to set the uri
        URI uri = clcCommands.getCurrentURI();
        t.setProxyState(clcCommands.toJSON());
        // Here's where we need to poke at this.
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        wrapper.sendRedirect(uri.toString());
    }

    /**
     * Sets up device flow with proxy and populates the {@link RFC8628State} with the information
     * from the proxy. This returns the proxy's user code.
     * @param oa2SE
     * @param t
     * @param rfc8628State
     * @return
     * @throws Exception
     */
    protected static String getProxyUserCode(OA2SE oa2SE, OA2ServiceTransaction t, RFC8628State rfc8628State) throws Exception {
        AuthorizationServletConfig asc = oa2SE.getAuthorizationServletConfig();
        OA2CLCCommands clcCommands = new OA2CLCCommands(true, oa2SE.getMyLogger(), new OA2CommandLineClient(oa2SE.getMyLogger()));
        clcCommands.load(new InputLine("dummy " + asc.getCfgName() + "  " + asc.getCfgFile()));
        clcCommands.set_param(new InputLine("set_param -a scope \"" + scopesToString(t) + "\""));
        clcCommands.df(new InputLine("df"));
        // Caveat. The device code is the auth grant from the proxy. We have to manage the one from
        // the proxy (to talk to that service) and the one from this server.
        // Do not set the device code here, let the CLC manage the one from the proxy.
        rfc8628State.userCode   = clcCommands.getUserCode();
        rfc8628State.lifetime = clcCommands.getDfExpiresIn();
        rfc8628State.interval = clcCommands.getDfInterval();
        t.setProxyState(clcCommands.toJSON());
        oa2SE.getTransactionStore().save(t); // save that proxy id!
        return rfc8628State.userCode;
    }
}
