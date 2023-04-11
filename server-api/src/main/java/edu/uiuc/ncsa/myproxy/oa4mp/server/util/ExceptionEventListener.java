package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.servlet.NotificationListener;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/18/12 at  11:27 AM
 */
public interface ExceptionEventListener extends NotificationListener {
    public void fireExceptionCaught(ExceptionEvent exceptionEvent);
}
