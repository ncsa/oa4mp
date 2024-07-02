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


CREATE DATABASE oa4mp
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

USE oa4mp;


CREATE TABLE oa4mp.clients
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

CREATE TABLE oa4mp.adminClients
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
    admin_id       VARCHAR(255),
    can_approve    BOOLEAN,
    can_create     BOOLEAN,
    can_read       BOOLEAN,
    can_remove     BOOLEAN,
    can_substitute tinyint(1) DEFAULT NULL,
    can_write      BOOLEAN,
    client_id      VARCHAR(255),
    creation_ts    timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    description    text,
    ersatz_id      text,
    permission_id  VARCHAR(255) PRIMARY KEY,
);

CREATE TABLE oa4mp.transactions
(
    access_token             TEXT,
    access_token_valid       tinyint(1)         DEFAULT NULL,
    at_jwt                   text,
    auth_grant               text,
    authz_grant_lifetime     bigint DEFAULT NULL,
    auth_time                timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    callback_uri             TEXT,
    certificate              TEXT,
    certlifetime             BIGINT,
    certreq                  TEXT,
    client_id                TEXT,
    expires_in               BIGINT,
    id_token_identifier      text,
    id_token_lifetime        bigint DEFAULT NULL,
    is_rfc_8628              tinyint(1) DEFAULT NULL,
    myproxyUsername          TEXT,
    nonce                    text,
    proxy_id                 text,
    refresh_token            TEXT,
    refresh_token_valid      BOOLEAN,
    refresh_token_expires_at bigint DEFAULT NULL,
    refresh_token_lifetime   bigint DEFAULT NULL,
    req_state                text,
    rt_jwt                   text,
    scopes                   text,
    states                   TEXT,
    temp_token               VARCHAR(255) PRIMARY KEY,
    temp_token_valid         BOOLEAN,
   user_code                 text,
    username                 TEXT,
    validated_scopes         text,
    verifier_token           TEXT,
    UNIQUE INDEX verifier (verifier_token(255)),
    UNIQUE INDEX accessToken (access_token(255)),
    UNIQUE INDEX refreshToken (refresh_token(255))
);

CREATE TABLE oa4mp.client_approvals
(
    client_id   VARCHAR(255) PRIMARY KEY,
    approver    TEXT,
    approved    BOOLEAN,
    description TEXT,
    status      TEXT,
    approval_ts TIMESTAMP
);

CREATE TABLE oa4mp.tx_records
(
    audience        text,
    description     text,
    expires_at      bigint,
    issued_at       bigint,
    issuer          text,
    lifetime        bigint,
    parent_id       text,
    resource        text,
    scopes          text,
    state           text,
    stored_token    text,
    token_id        VARCHAR(255) PRIMARY KEY,
    token_type      text,
    token           text,
    valid           boolean,
    INDEX parents (parent_id(255))
);


COMMIT;
CREATE TABLE oa4mp.virtual_organizations
(
    at_issuer      text,
    created        bigint,
    default_key_id text,
    discovery_path text,
    issuer         text,
    json_web_keys  text,
    last_modified  bigint,
    resource       text,
    title          text,
    valid          boolean,
    vo_id          VARCHAR(255) PRIMARY KEY,
    INDEX discovery_path (discovery_path(255))
);
# Now to grant restricted access. The  tables have to exist before this step

GRANT All ON oa4mp.client_approvals TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.clients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.adminClients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.transactions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.permissions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.tx_records TO 'oa4mp-server'@'localhost';
GRANT ALL ON oa4mp.virtual_organizations TO 'oa4mp-server'@'localhost';

commit;
