package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things;

/**
 * Interface with constants for Subject, Action and Target
 * <p>Created by Jeff Gaynor<br>
 * on 10/10/16 at  10:31 AM
 */
public interface SAT {
    public static final int SUBJECT_UNKNOWN_VALUE = -1;
    public static final String KEYS_API = "api";
    public static final String SUBJECT_CLIENT = "client";
    public static final int SUBJECT_CLIENT_VALUE = 0;
    public static final String SUBJECT_ADMIN = "admin";
    public static final int SUBJECT_ADMIN_VALUE = 1;
    public static final int TYPE_UNKNOWN_VALUE = -10;
    public static final int TYPE_ADMIN_VALUE = 10;
    public static final String TYPE_ATTRIBUTE = "attribute";
    public static final int TYPE_ATTRIBUTE_VALUE = 11;
    public static final String TYPE = "client";
    public static final int TYPE_CLIENT_VALUE = 12;
    public static final String KEYS_TYPE = "type";
    public static final String TYPE_ADMIN = "admin";
    public static final String TYPE_CLIENT = "client";
    public static final String TYPE_PERMISSION = "permission";
    public static final int TYPE_PERMISSION_VALUE = 13;
    public static final int ACTION_UNKNOWN_VALUE = -100;
    public static final String ACTION_GET = "get";
    public static final int ACTION_GET_VALUE = 100;
    public static final String ACTION_SET = "set";
    public static final int ACTION_SET_VALUE = 101;
    public static final String ACTION_REMOVE = "remove";
    public static final int ACTION_REMOVE_VALUE = 102;
    public static final String ACTION_ADD = "add";
    public static final int ACTION_ADD_VALUE = 103;
    public static final String ACTION_LIST = "list";
    public static final int ACTION_LIST_VALUE = 104;
    public static final String ACTION_EXECUTE = "execute";
    public static final int ACTION_EXECUTE_VALUE = 105;
    public static final String ACTION_APPROVE = "approve";
    public static final int ACTION_APPROVE_VALUE = 106;
    public static final String ACTION_CREATE = "create";
    public static final int ACTION_CREATE_VALUE = 107;
    public static final String ACTION_UNAPPROVE = "unapprove";
    public static final int ACTION_UNAPPROVE_VALUE = 108;
    public static final String TARGET_ADMIN = "admin";
    public static final int TARGET_ADMIN_VALUE = 1000;
    public static final String TARGET_CLIENT = "client";
    public static final int TARGET_CLIENT_VALUE = 1001;
    public static final int TARGET_NO_VALUE = 1002;
      public static final String KEYS_SUBJECT = "subject";

    public static final int KEYS_SUBJECT_VALUE = 200;
    public static final String KEYS_ACTION = "action";
    public static final String KEYS_METHOD = "method";
    public static final int KEYS_ACTION_VALUE = 201;
    public static final String KEYS_TARGET = "object";
    public static final int KEYS_TARGET_VALUE = 202;
    public static final String KEYS_ID = "id";
    public static final int KEYS_ID_VALUE = 203;
    public static final String KEYS_CONTENT = "content";
    public static final int KEYS_CONTENT_VALUE = 204;
}
