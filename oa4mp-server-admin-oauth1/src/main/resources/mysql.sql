/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* variable
   support, everything is hard-coded. if you want something other than the default names and 
   then edit the file.
*/


CREATE USER 'oa4mp-server'@'localhost'
  IDENTIFIED BY 'PASSWORD';

CREATE DATABASE oauth
  DEFAULT CHARACTER SET utf8;
USE oauth;

# Set permissions. The permissions must be granted in MySQL before the tables are created.
GRANT ALL PRIVILEGES ON oauth.transactions TO 'oa4mp-server'@'localhost';
GRANT ALL PRIVILEGES ON oauth.client_approvals TO 'oa4mp-server'@'localhost';
GRANT ALL PRIVILEGES ON oauth.clients TO 'oa4mp-server'@'localhost';

COMMIT;

CREATE TABLE oauth.clients (
  oauth_consumer_key  VARCHAR(255) PRIMARY KEY,
  oauth_client_pubkey TEXT,
  name                TEXT,
  home_url            TEXT,
  error_url           TEXT,
  email               TEXT,
  proxy_limited       BOOLEAN,
  creation_ts         TIMESTAMP
);


CREATE TABLE oauth.client_approvals (
  oauth_consumer_key VARCHAR(255),
  approver           TEXT,
  approved           BOOLEAN,
  approval_ts        TIMESTAMP
);


CREATE TABLE oauth.transactions (
  temp_token         VARCHAR(255) PRIMARY KEY,
  temp_token_valid   BOOLEAN,
  oauth_callback     TEXT,
  certreq            TEXT,
  certlifetime       BIGINT,
  oauth_consumer_key TEXT,
  oauth_verifier     TEXT,
  access_token       TEXT,
  access_token_valid BOOLEAN,
  certificate        TEXT,
  username           TEXT,
  myproxyUsername    TEXT,
  UNIQUE INDEX verifier (oauth_verifier(255)),
  UNIQUE INDEX accessToken (access_token(255))
);

COMMIT;
