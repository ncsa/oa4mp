package edu.uiuc.ncsa.myproxy.oauth2.tools.migrate;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/5/24 at  7:20 AM
 */
public interface MigrationConstants {
    // Success codes
    int IMPORT_CODE_NOT_DONE = 0;
    int IMPORT_CODE_SUCCESS = 1;
    int IMPORT_CODE_UPKEEP_TEST_ONLY = 2;

    int IMPORT_CODE_UPKEEP_ARCHIVED = 3;

    int IMPORT_CODE_FILE_NOT_FOUND = -1;
    String IMPORT_MESSAGE_FILE_NOT_FOUND = "file not found";
    int IMPORT_CODE_FILE_PERMISSION = -2;
    String IMPORT_MESSAGE_FILE_PERMISSION = "does not have read access";
    int IMPORT_CODE_FILE_IS_A_DIRECTORY = -3;
    String IMPORT_MESSAGE_FILE_IS_A_DIRECTORY = "is a directory";
    int IMPORT_CODE_PARSE_ERROR = -4;
    String IMPORT_MESSAGE_PARSE_ERROR = "cannot parse entry";
    int IMPORT_CODE_UNKNOWN_ERROR = -5;
    String IMPORT_MESSAGE_UNKNOWN_ERROR = "unknown error";
    String IMPORT_MESSAGE_UNKNOWN_ERROR_CODE = "unknown error code";
    int IMPORT_CODE_EMPTY_FILE = -6;
    String IMPORT_MESSAGE_EMPTY_FILE = "file is empty";
    int IMPORT_CODE_COULD_NOT_READ = -7;
    String IMPORT_MESSAGE_COULD_NOT_READ = "could not read file";
    int IMPORT_CODE_UPKEEP_SKIPPED = -8;
    String IMPORT_MESSAGE_UPKEEP_SKIPPED = "skipped by upkeep";


    /**
     * Use after random throwable error. Add the specific failure
     */
    int IMPORT_CODE_OTHER_ERROR = -9;
    String IMPORT_MESSAGE_OTHER_ERROR = "";

    int IMPORT_CODE_MISSING_ID = -10;
    String IMPORT_MESSAGE_MISSING_ID = "missing identifier: entry improperly structured";

    int IMPORT_CODE_UPKEEP_DELETED = -11;
    int IMPORT_CODE_NO_CORRESPONDING_ENTRY = -12;
    String IMPORT_MESSAGE_NO_CORRESPONDING_ENTRY = "no main entry for this object";


    int[] ALL_FAILURE_CODES = new int[]{IMPORT_CODE_FILE_NOT_FOUND,
            IMPORT_CODE_FILE_PERMISSION,
            IMPORT_CODE_FILE_IS_A_DIRECTORY,
            IMPORT_CODE_PARSE_ERROR,
            IMPORT_CODE_UNKNOWN_ERROR,
            IMPORT_CODE_EMPTY_FILE,
            IMPORT_CODE_COULD_NOT_READ,
            IMPORT_CODE_UPKEEP_SKIPPED,
            IMPORT_CODE_UPKEEP_DELETED,
            IMPORT_CODE_OTHER_ERROR,
            IMPORT_CODE_MISSING_ID,
            IMPORT_CODE_NO_CORRESPONDING_ENTRY};

    static String getImportMessage(int importCode) {
        switch (importCode) {
            case IMPORT_CODE_FILE_NOT_FOUND:
                return IMPORT_MESSAGE_FILE_NOT_FOUND;
            case IMPORT_CODE_EMPTY_FILE:
                return IMPORT_MESSAGE_EMPTY_FILE;
            case IMPORT_CODE_FILE_IS_A_DIRECTORY:
                return IMPORT_MESSAGE_FILE_IS_A_DIRECTORY;
            case IMPORT_CODE_FILE_PERMISSION:
                return IMPORT_MESSAGE_FILE_PERMISSION;
            case IMPORT_CODE_PARSE_ERROR:
                return IMPORT_MESSAGE_PARSE_ERROR;
            case IMPORT_CODE_NOT_DONE:
                return null;
            case IMPORT_CODE_COULD_NOT_READ:
                return IMPORT_MESSAGE_COULD_NOT_READ;
            case IMPORT_CODE_OTHER_ERROR:
                return IMPORT_MESSAGE_OTHER_ERROR;
            case IMPORT_CODE_UNKNOWN_ERROR:
                return IMPORT_MESSAGE_UNKNOWN_ERROR;
            case IMPORT_CODE_MISSING_ID:
                return IMPORT_MESSAGE_MISSING_ID;
            case IMPORT_CODE_NO_CORRESPONDING_ENTRY:
                return IMPORT_MESSAGE_NO_CORRESPONDING_ENTRY;
            case IMPORT_CODE_UPKEEP_SKIPPED:
                return IMPORT_MESSAGE_UPKEEP_SKIPPED;
            default:
                return IMPORT_MESSAGE_UNKNOWN_ERROR_CODE;
        }
    }

}
