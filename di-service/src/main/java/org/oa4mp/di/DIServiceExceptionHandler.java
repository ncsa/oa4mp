package org.oa4mp.di;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.servlet.ExceptionHandlerThingie;
import org.oa4mp.delegation.server.OA2Errors;
import org.oa4mp.delegation.server.OA2GeneralError;
import org.oa4mp.server.loader.oauth2.servlet.OA2ExceptionHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.oa4mp.di.DIService.STATUS_EXPIRED_TOKEN;
import static org.oa4mp.di.DIService.STATUS_MALFORMED_SCOPE;
import static org.oa4mp.di.StatusCodes.STATUS_CLIENT_NOT_FOUND;


/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/29/21 at  10:56 AM
 */
public class DIServiceExceptionHandler extends OA2ExceptionHandler implements OA2Errors {

    public DIServiceExceptionHandler(DIService diService, MyLoggingFacade logger) {
        super(logger);
        this.diService = diService;
    }
    DIService diService;
    @Override
    public void handleException(ExceptionHandlerThingie xh) throws IOException, ServletException {
        Throwable t = xh.throwable;
        HttpServletRequest request=xh.request;
        HttpServletResponse response = xh.response;
        if (t instanceof OA2GeneralError) {
            OA2GeneralError ge = (OA2GeneralError) t;
            Err err = new Err(StatusCodes.STATUS_INTERNAL_ERROR, ge.getError(), ge.getDescription());
            diService.writeMessage(response, err);
            return;
        }
        super.handleException(xh);

    }

    /**
     * Yet Another {@link Err} type object. This links
     * {@link OA2Errors} to {@link StatusCodes}.
     * Note that not setting the message to null means that whatever description OA4MP
     * generated will be used. These are generally very informative for system programmers
     * but not necessarily so for end users. This allows customization.
     */
    public static class YAErr {
        public YAErr(int code, String message) {
            this.code = code;
            this.message = message;
        }

        int code;
        String message;
        public boolean hasMessage(){return message!= null;}

        @Override
        public String toString() {
            return "YAErr{" +
                    "code=" + code +
                    ", message='" + message + '\'' +
                    '}';
        }
    }



    /**
     * A practical note is that an awful lot of the errors that OA4MP generates are edge cases
     * (such as a non-existent response_type) or very marginal at best. Generally the OA4MP
     * errors are pretty succinct about what happened. E.g. {@link OA2Errors#INVALID_GRANT}
     * may refer to any of
     * <ul>
     *     <li>an expired authorization grant</li>
     *     <li>an authorization grant that has been invalidated (probably be cause it was used already</li>
     *     <li>an authorization grant that is legitimately past expiration</li>
     *     <li>a bogus authorization grant that is unreocognized by the system.</li>
     * </ul>
     * This will be disambiguated in the description of the {@link OA2GeneralError}
     * that is thrown. This method will let you override any or all of these messages
     * as you see fit.
     * @param oa2Error
     * @return
     */
    public static YAErr lookupErrorCode(String oa2Error) {
        switch (oa2Error) {
            case OA2Errors.INTERACTION_REQUIRED:
                return new YAErr(org.oa4mp.di.StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.LOGIN_REQUIRED:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.ACCOUNT_SELECTION_REQUIRED:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.CONSENT_REQUIRED:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.INVALID_REQUEST_OBJECT:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.INVALID_REQUEST:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.INVALID_REQUEST_URI:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.UNAUTHORIZED_CLIENT:
                return new YAErr(STATUS_CLIENT_NOT_FOUND, null);
            case OA2Errors.ACCESS_DENIED:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.UNSUPPORTED_RESPONSE_TYPE:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.INVALID_SCOPE:
                return new YAErr(STATUS_MALFORMED_SCOPE, null);
            case OA2Errors.TEMPORARILY_UNAVAILABLE:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.SERVER_ERROR:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            case OA2Errors.INVALID_TOKEN:
                return new YAErr(STATUS_EXPIRED_TOKEN, null);
            case OA2Errors.INVALID_GRANT:
                return new YAErr(STATUS_EXPIRED_TOKEN, null);
            case OA2Errors.INVALID_TARGET:
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, null);
            default:
                // If some error is generated this system does not recognize, it will return this.
                return new YAErr(StatusCodes.STATUS_INTERNAL_ERROR, "general error");
        }
    }
}
