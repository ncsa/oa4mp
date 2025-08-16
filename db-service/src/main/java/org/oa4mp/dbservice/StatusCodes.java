package org.oa4mp.dbservice;

import static org.oa4mp.dbservice.DBService.*;

/**
 * Lookup utility relating codes to human-readable error message
 * <p>Created by Jeff Gaynor<br>
 * on 1/28/21 at  6:56 AM
 */
public class StatusCodes {
    /*
    Success codes
     */
    public static final int STATUS_OK = 0x0; // 0
    public static final int STATUS_ACTION_NOT_FOUND = 0x1; //1
    public static final int STATUS_NEW_USER = 0x2; //2
    public static final int STATUS_USER_SERIAL_STRING_UPDATED = 0x4; //4
    public static final int STATUS_USER_NOT_FOUND = 0x6;  //6
    public static final int STATUS_USER_EXISTS = 0x8; //8
    public static final int STATUS_IDP_UPDATED = 0xA; //8
    /*
    error codes
     */
    public static final int STATUS_USER_EXISTS_ERROR = 0xFFFA1; //1048481
    public static final int STATUS_USER_NOT_FOUND_ERROR = 0xFFFA3; // 1048483
    public static final int STATUS_TRANSACTION_NOT_FOUND = 0xFFFA5; //1048485
    public static final int STATUS_IDP_SAVE_FAILED = 0xFFFA7; // 1048487
    public static final int STATUS_DUPLICATE_ARGUMENT = 0xFFFF1; // 1048561
    public static final int STATUS_INTERNAL_ERROR = 0xFFFF3; // 1048563 was "database failure"
    public static final int STATUS_SAVE_IDP_FAILED = 0xFFFF5; // 1048565
    public static final int STATUS_MALFORMED_INPUT = 0xFFFF7; // 1048567
    public static final int STATUS_MISSING_ARGUMENT = 0xFFFF9; // 1048569
    public static final int STATUS_NO_REMOTE_USER = 0xFFFFB; // 1048571
    public static final int STATUS_NO_IDENTITY_PROVIDER = 0xFFFFD; // 1048573
    public static final int STATUS_CLIENT_NOT_FOUND = 0xFFFFF; // 1048575
    public static final int STATUS_EPTID_MISMATCH = 0x100001; // 1048577
    public static final int STATUS_PAIRWISE_ID_MISMATCH = 0x100003; // 1048579
    public static final int STATUS_SUBJECT_ID_MISMATCH = 0x100005; // 1048581


    /**
     * Gets the preset CILogon error description from the DB Service error status.
     *
     * @param status
     * @return
     */
    public static String getMessage(int status) {
        switch (status) {
            case STATUS_OK:
                return "Status OK.";
            case STATUS_ACTION_NOT_FOUND: //1
                return "Action not found.";
            case STATUS_NEW_USER: //2
                return "New user created.";
            case STATUS_USER_SERIAL_STRING_UPDATED: //4
                return "User data updated.";
            case STATUS_USER_NOT_FOUND:  //6
                return "User not found.";
            case STATUS_USER_EXISTS: //8
                return "User exists."; // informational message
            case STATUS_USER_EXISTS_ERROR: //1048481
                return "User already exists."; // actual error that the user should not exist.
            case STATUS_USER_NOT_FOUND_ERROR: // 1048483
                return "User not found.";
            case STATUS_TRANSACTION_NOT_FOUND: //1048485
                return "Transaction not found.";
            case STATUS_IDP_SAVE_FAILED: // 1048487
                return "Could not save IdPs.";
            case STATUS_DUPLICATE_ARGUMENT: // 1048561
                return "Duplicate parameter.";
            case STATUS_INTERNAL_ERROR: // 1048563 was "database failure"
                return "Internal error.";
            case STATUS_SAVE_IDP_FAILED: // 1048565
                return "Could not save IdP.";
            case STATUS_MALFORMED_INPUT: // 1048567
                return "Malformed input.";
            case STATUS_MISSING_ARGUMENT: // 1048569
                return "Missing parameter.";
            case STATUS_NO_REMOTE_USER: // 1048571
                return "Missing remote user.";
            case STATUS_NO_IDENTITY_PROVIDER: // 1048573
                return "Missing IdP.";
            case STATUS_CLIENT_NOT_FOUND: // 1048575
                return "Missing client.";
            case STATUS_EPTID_MISMATCH: // 1048577
                return "EPTID mismatch.";
            case STATUS_PAIRWISE_ID_MISMATCH: // 1048579
                return "Pairwise ID mismatch.";
            case STATUS_SUBJECT_ID_MISMATCH: // 1048581
                return "Subject ID mismatch.";
            // CIL-1625 DBService errors should have their own descriptions, not just default to "unknown error"
            case DBService.STATUS_TRANSACTION_NOT_FOUND:  // 0x10001 = 65537
                return "transaction not found";
            case STATUS_EXPIRED_TOKEN: // 0x10003 =65539
                return "expired token";
            case STATUS_CREATE_TRANSACTION_FAILED: //  0x10005 = 65541
                return "create transaction failed";
            case STATUS_MISSING_CLIENT_ID: // 0x10009 = 65545
                return "missing client id";
            case STATUS_UNKNOWN_CLIENT: // 0x1000D = 65549
                return "unknown client";
            case STATUS_UNAPPROVED_CLIENT: //0x1000F = 65551
                return "unapproved client";
            case STATUS_NO_SCOPES: //0x10011 = 65553
                return "no scopes found";
            case STATUS_MALFORMED_SCOPE: // 0x10013 = 65555
                return "malformed scope";
            case STATUS_SERVICE_UNAVAILABLE:// 0x10015 = 65557
                return "service unavailable";
            case STATUS_QDL_ERROR: // 0x100007 = 1048583
                return "qdl error";
            case STATUS_QDL_RUNTIME_ERROR: // 0x100009 = 1048585
                return "qdl runtime error";
            default:
                return "Unknown error 0x" + Integer.toHexString(status) + " = " + status;
        }
    }
}
