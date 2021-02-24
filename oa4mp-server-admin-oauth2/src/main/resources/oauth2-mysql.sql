/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* variable
   support, everything is hard-coded. if you want something other than the default names and 
   then edit the file.
*/

/*
Usage: Log in as an administrator (such as root) that can create the user, if need be.

CREATE USER 'oa4mp-server'@'localhost' IDENTIFIED BY 'PASSWORD';

Run the rest of this script. The user must exist before permissions are granted.
*/


CREATE DATABASE oauth2
    DEFAULT CHARACTER SET utf8;

/*
Some useful commands. Lst two list users and will show permissions for a single user on a machine.:
 Show Databases;
 Show schemas;
 SELECT User FROM mysql.user;
 SHOW GRANTS FOR 'user'@'localhost';
 Another note: The timestamp fields are given a default value of NULL since under MariaDB the default now is to
 change the value of any timestamp field on update, effectively rendering all of the "last modified"
 */

USE oauth2;


CREATE TABLE oauth2.clients
(
    client_id        VARCHAR(255) PRIMARY KEY,
    public_key       TEXT,
    name             TEXT,
    home_url         TEXT,
    error_url        TEXT,
    issuer           TEXT,
    ldap             TEXT,
    email            TEXT,
    scopes           TEXT,
    proxy_limited    BOOLEAN,
    public_client    BOOLEAN,
    creation_ts      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    rt_lifetime      bigint,
    callback_uri     TEXT,
    sign_tokens      BOOLEAN,
    cfg              TEXT
);

CREATE TABLE oauth2.adminClients
(
    admin_id         VARCHAR(255) PRIMARY KEY,
    name             TEXT,
    secret           TEXT,
    email            TEXT,
    creation_ts      timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    vo               TEXT,
    max_clients      BIGINT,
    issuer           TEXT,
    config           TEXT
);


CREATE TABLE permissions
(
    permission_id VARCHAR(255) PRIMARY KEY,
    admin_id      VARCHAR(255),
    client_id     VARCHAR(255),
    can_approve   BOOLEAN,
    can_create    BOOLEAN,
    can_read      BOOLEAN,
    can_remove    BOOLEAN,
    can_write     BOOLEAN,
    creation_ts   TIMESTAMP
);

CREATE TABLE oauth2.client_approvals
(
    client_id   VARCHAR(255) PRIMARY KEY,
    approver    TEXT,
    approved    BOOLEAN,
    status      TEXT,
    approval_ts TIMESTAMP
);

CREATE TABLE oauth2.transactions
(
    temp_token          VARCHAR(255) PRIMARY KEY,
    temp_token_valid    BOOLEAN,
    callback_uri        TEXT,
    certreq             TEXT,
    certlifetime        BIGINT,
    client_id           TEXT,
    verifier_token      TEXT,
    access_token        TEXT,
    refresh_token       TEXT,
    refresh_token_valid BOOLEAN,
    expires_in          BIGINT,
    states              TEXT,
    certificate         TEXT,
    username            TEXT,
    myproxyUsername     TEXT,
    access_token_valid  tinyint(1)         DEFAULT NULL,
    auth_time           timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    nonce               text,
    scopes              text,
    UNIQUE INDEX verifier (verifier_token(255)),
    UNIQUE INDEX accessToken (access_token(255)),
    UNIQUE INDEX refreshToken (refresh_token(255))
);

CREATE TABLE oauth2.tx_records
(
    token_id   VARCHAR(255) PRIMARY KEY,
    lifetime   bigint,
    issued_at  bigint,
    expires_at bigint,
    parent_id  text,
    token_type text,
    valid      boolean,
    scopes     text,
    audience   text,
    issuer     text,
    resource   text,
    INDEX parents (parent_id(255))
);


CREATE TABLE oauth2.virtual_organizations
(
    vo_id          VARCHAR(255) PRIMARY KEY,
    created        bigint,
    default_key_id text,
    discovery_path text,
    issuer         text,
    json_web_keys  text,
    last_modified  bigint,
    title           text,
    resource       text,
    valid          boolean,
    UNIQUE INDEX parents (vo_id(255)),
    INDEX discovery_path (discovery_path(255))
);
COMMIT;
# Now to grant restricted access. The  tables have to exist before this step

GRANT All ON oauth2.client_approvals TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.clients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.adminClients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.transactions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.permissions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.tx_records TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.virtual_organizations TO 'oa4mp-server'@'localhost';

commit;
