package org.oa4mp.server.loader.oauth2.servlet;

import org.oa4mp.server.api.storage.servlet.AbstractInitServlet;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.IssuerResponse;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  2:01 PM
 */
public class OA2AuthorizedServlet extends AbstractInitServlet {
    protected OA2AuthorizedServletUtil initUtil = null;

    public OA2AuthorizedServletUtil getInitUtil() {
        if(initUtil == null){
            initUtil = new OA2AuthorizedServletUtil(this);
        }
        return initUtil;
    }

    @Override
    protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
        getInitUtil().doIt(httpServletRequest,httpServletResponse);
    }


    @Override
    public ServiceTransaction verifyAndGet(IssuerResponse iResponse) throws IOException {
        throw new NFWException("Error: not implemented.");
    }
}
