package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.Notifier;
import edu.uiuc.ncsa.security.util.mail.MailUtil;

import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/18/12 at  11:27 AM
 */
public class ExceptionEventNotifier extends Notifier implements ExceptionEventListener {
    public ExceptionEventNotifier(MailUtil mailUtil, MyLoggingFacade loggingFacade) {
        super(mailUtil, loggingFacade);
    }

    @Override
    public void fireExceptionCaught(ExceptionEvent exceptionEvent) {
        loggingFacade.info("preparing to send notice for exception");
        Map<String, String> params = exceptionEvent.getState();
        mailUtil.sendMessage(params);
    }
}
