package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.ClientManager;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import net.sf.json.JSON;
import net.sf.json.JSONSerializer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;

/**
 * The client management servlet.
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  11:41 AM
 */
public class ClientServlet extends EnvServlet {


    @Override
    public void doGet(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws ServletException, IOException {
        throw new NotImplementedException("Get is not supported by this service");
    }

    public ClientManager getClientManager() {
        if (clientManager == null) {
            clientManager = new ClientManager((ServiceEnvironmentImpl) getEnvironment());
        }
        return clientManager;
    }

    ClientManager clientManager;

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        printAllParameters(httpServletRequest);
        BufferedReader br = httpServletRequest.getReader();
        System.err.println("query=" + httpServletRequest.getQueryString());
        StringBuffer stringBuffer = new StringBuffer();
        String line = br.readLine();
        System.err.println("line=" + line);
        while (line != null) {
            stringBuffer.append(line);
            line = br.readLine();
        }
        br.close();
        if (stringBuffer.length() == 0) {
            throw new IllegalArgumentException("Error: There is no content for this request");
        }
        JSON json = JSONSerializer.toJSON(stringBuffer.toString());
        System.err.println(json.toString());
        if (json.isArray()) {
            getMyLogger().info("Error: Got a JSON array rather than a request:" + json);
            throw new IllegalArgumentException("Error: incorrect argument. Not a valid JSON request");
        }
        getClientManager().equals(json);
    }


}
