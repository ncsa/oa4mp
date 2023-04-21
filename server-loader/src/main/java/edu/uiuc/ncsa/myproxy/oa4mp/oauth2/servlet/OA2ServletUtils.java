package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2ATException;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.ScriptRuntimeException;
import edu.uiuc.ncsa.qdl.exceptions.AssertionException;
import edu.uiuc.ncsa.qdl.exceptions.ParsingException;
import edu.uiuc.ncsa.qdl.exceptions.QDLExceptionWithTrace;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import edu.uiuc.ncsa.security.storage.GenericStoreUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import org.apache.http.HttpStatus;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * Utilities for various servlets. These handle the exceptions from the script runtime engine and perform
 * a full rollback. These are messy, but unavoidable.
 * <p>Created by Jeff Gaynor<br>
 * on 4/26/22 at  6:52 AM
 */
public class OA2ServletUtils {
    public static int stackTraceMaxLines = 5;

    public static void handleScriptEngineException(Object callingObject,
                                                   OA2SE oa2SE,
                                                   Throwable t,
                                                   MetaDebugUtil debugger,
                                                   OA2ServiceTransaction transaction,
                                                   XMLMap tBackup) {
        handleScriptEngineException(callingObject, oa2SE, t, debugger, transaction, tBackup, null);

    }

    /**
     * @param callingObject
     * @param oa2SE
     * @param exception
     * @param debugger
     * @param transaction
     * @param tBackup
     * @param txRecord
     */
    public static void handleScriptEngineException(Object callingObject,
                                                   OA2SE oa2SE,
                                                   Throwable exception,
                                                   MetaDebugUtil debugger,
                                                   OA2ServiceTransaction transaction,
                                                   XMLMap tBackup,
                                                   TXRecord txRecord) {
        // Rollback and allow someone to fix the problem. Proceeding (i.e. catching the exception rather than
        // rethrowing it) would mean that the transaction will complete
        // and the old tokens would be invalid, replaced by new ones, so don't do that.
        // Hard stop here and let someone have a chance to fix the issue.
        rollback(oa2SE, tBackup, txRecord);
        OA2ATException atException = null;
        String message = null;
        if (exception instanceof OA2ATException) {
            // if the exception is already an OA2ATException, just pass it along, but take care
            // of error logging first.
            ppξ(exception, callingObject, oa2SE, debugger, exception.getMessage()); // decide what to print in the logs.
            throw (OA2ATException) exception;

        }
        if (exception instanceof QDLExceptionWithTrace) {
            // CIL-1267 make sure error propagates.
            // This can happen if something very deep in the stack (non QDL) blows up and QDL
            // has caught it.

            message = "error processing request:" + exception.getMessage();
            atException = new OA2ATException(OA2Errors.INVALID_REQUEST,
                    message,
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getClient());
        }
        if (exception instanceof AssertionException) {
            // they passed a bad argument to a QDL script
            message = "assertion exception:" + exception.getMessage();
            atException = new OA2ATException(OA2Errors.INVALID_REQUEST,
                    message,
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getClient());
        }

        if (exception instanceof ScriptRuntimeException) {
            // QDL script threw an exception. Usually this means there is missing information from e.g. LDAP.
            // Let the user try and figure everything out and try again.
            ScriptRuntimeException sre = (ScriptRuntimeException) exception;

            message = "script runtime exception: \"" + sre.getMessage() + "\"";
            // message in the exception should be exactly what the script threw, but we add a note about its origin.
            if (sre.getErrorURI() == null) {
                atException = new OA2ATException(sre.getRequestedType(),
                        sre.getMessage(),
                        sre.getHttpStatus(),
                        transaction.getRequestState(),
                        transaction.getClient());
            } else {
                atException = new OA2ATException(sre.getRequestedType(),
                        sre.getMessage(),
                        sre.getHttpStatus(),
                        sre.getErrorURI(),
                        transaction.getRequestState(),
                        transaction.getClient());
            }
        }
        if(exception instanceof ParsingException){
            ParsingException parsingException=(ParsingException)exception;
            String msg;
            if(parsingException.hasScriptName()){
                msg = "error parsing script '" + parsingException.getScriptName() + "' ";
            }else{
                msg = "parser error " ;
            }
            msg = msg + "at line # " + parsingException.getLineNumber() +
                                    ", char=" + parsingException.getEndCharacterPosition();
            debugger.trace(OA2ServletUtils.class, msg, exception);
            // This will get wrapped in an OA2ATException below, but parsing errors should have a note in the logs
            // since we have to track these down as QDL errors.
        }
        if (exception instanceof IllegalAccessException) {
            // Most generic exception possible.
            // *Possible* from servlet. Mostly catching it here since otherwise the user gets something
            // completely confusing.
            message = "illegal access exception \"" + exception.getMessage() + "\"";
            atException = new OA2ATException(OA2Errors.UNAUTHORIZED_CLIENT,
                    "access denied",
                    transaction.getRequestState(),
                    transaction.getClient());
        }
        // Everything else.
        if (atException == null) {
            // fall-through case.
            message = "unable to update claims on token refresh: \"" + exception.getMessage() + "\"";
            atException = new OA2ATException(OA2Errors.INVALID_REQUEST,
                    message,
                    HttpStatus.SC_BAD_REQUEST,
                    transaction.getRequestState(),
                    transaction.getClient());

        }

        ppξ(exception, callingObject, oa2SE, debugger, message); // decide what to print in the logs.
        throw atException;
    }

    protected static void rollback(OA2SE oa2SE, XMLMap backup, TXRecord txRecord) {
        GenericStoreUtils.fromXMLAndSave(oa2SE.getTransactionStore(), backup);
        if (txRecord != null) {
            oa2SE.getTxStore().remove(txRecord.getIdentifier());
        }
    }


    /**
     * Take a stack trace and print the first n lines of it.
     *
     * @param e
     * @param n
     * @return the truncated stack trace
     */
    public static String truncateStackTrace(Throwable e, int n, boolean printIt) {
        String current = truncateStackTrace2(e, n, printIt);
        Throwable nextE = e.getCause();
        if (nextE != null) {
            for (int i = 1; i < n; i++) {
                current = current + "\n" + truncateStackTrace2(nextE, n, printIt);
                nextE = nextE.getCause();
                if (nextE == null) {
                    break; // jump out, we are done.
                }
            }
        }
        return current;
    }

    protected static String truncateStackTrace2(Throwable e, int n, boolean printIt) {
        StringWriter writer = new StringWriter();
        e.printStackTrace(new PrintWriter(writer));
        String[] lines = writer.toString().split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(lines.length, n); i++) {
            sb.append(lines[i]).append("\n");
        }
        if (printIt) {
            System.err.println(sb);
        }
        return sb.toString();
    }

    /**
     * Pretty print the exception. This decides what to print and shortens the stack trace.
     *
     * @param throwable
     * @param callingObject
     * @param debugger
     * @param message
     */
    protected static void ppξ(Throwable throwable,
                              Object callingObject,
                              OA2SE oa2SE,
                              MetaDebugUtil debugger,  // if null, forces output.
                              String message) {
        if (debugger == null) {
            oa2SE.warn(message);
            oa2SE.warn(truncateStackTrace(throwable, stackTraceMaxLines, false));
            return;
        }
        debugger.trace(callingObject, message);
        debugger.trace(callingObject, truncateStackTrace(throwable, stackTraceMaxLines, false));
    }
}
