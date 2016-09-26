package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.servlet.NotificationListener;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/18/12 at  10:36 AM
 */
public interface NewClientListener extends NotificationListener {
    public void fireNewClientEvent(NewClientEvent newClientEvent);
}
