/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* varaible
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
USE oauth2;

/*
Some useful commands. Lst two list users and will show permissions for a single user on a machine.:
 Show Databases;
 Show schemas;
 SELECT User FROM mysql.user;
 SHOW GRANTS FOR 'user'@'localhost';
 */

CREATE TABLE oauth2.clients (
  client_id     VARCHAR(255) PRIMARY KEY,
  public_key    TEXT,
  name          TEXT,
  home_url      TEXT,
  error_url     TEXT,
  email         TEXT,
  proxy_limited BOOLEAN,
  creation_ts   TIMESTAMP,
  rt_lifetime bigint,
  callback_uri  TEXT
);


CREATE TABLE oauth2.adminClients (
  admin_id     VARCHAR(255) PRIMARY KEY,
  name         TEXT,
  secret       TEXT,
  email        TEXT,
  creation_ts  TIMESTAMP,
  vo           TEXT,
  issuer       TEXT
);

CREATE TABLE oauth2.ldap(
  id            VARCHAR(255) PRIMARY KEY,
  client_id     VARCHAR(255),
  ldap          LONGTEXT,
  UNIQUE INDEX client_id (client_id(255))
);


CREATE TABLE oauth2.permissions (
  permission_id VARCHAR(255) PRIMARY KEY,
  admin_id      VARCHAR(255),
  client_id     VARCHAR(255),
  can_approve   BOOLEAN,
  can_create    BOOLEAN,
  can_read      BOOLEAN,
  can_remove    BOOLEAN,
  can_write     BOOLEAN,
  creation_ts   TIMESTAMP,
  UNIQUE INDEX admin_id (admin_id(255)),
  UNIQUE INDEX client_id (client_id(255))
);

CREATE TABLE oauth2.client_approvals (
  client_id   VARCHAR(255) PRIMARY KEY,
  approver    TEXT,
  approved    BOOLEAN,
  approval_ts TIMESTAMP
);

CREATE TABLE oauth2.transactions (
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
  certificate         TEXT,
  username            TEXT,
  myproxyUsername     TEXT,
  access_token_valid tinyint(1) DEFAULT NULL,
  auth_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  nonce text,
  scopes text,
  UNIQUE INDEX verifier (verifier_token(255)),
  UNIQUE INDEX accessToken (access_token(255)),
  UNIQUE INDEX refreshToken (refresh_token(255)),
  UNIQUE INDEX username (username(255))
);


COMMIT;
# Now to grant restricted access. The  tables have to exist before this step

GRANT All  ON oauth2.client_approvals TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.clients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.adminClients TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.transactions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.permissions TO 'oa4mp-server'@'localhost';
GRANT ALL ON oauth2.ldap TO 'oa4mp-server'@'localhost';

commit;
