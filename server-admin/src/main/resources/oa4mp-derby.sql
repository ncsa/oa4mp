
/* Uncomment this if you did not do the test above and have already created the schema.
CREATE SCHEMA oauth2;
*/
CREATE SCHEMA oauth2;


CREATE TABLE oauth2.transactions
(
    access_token              VARCHAR(255),
    access_token_valid        boolean,
    at_jwt                    clob,
    auth_grant                clob,
    auth_time                 timestamp,
    authz_grant_lifetime      bigint,
    callback_uri              clob,
    certificate               clob,
    certlifetime              bigint,
    certreq                   clob,
    client_id                 clob,
    description               clob,
    expires_in                bigint,
    id_token_identifier       clob,
    id_token_lifetime         bigint,
    is_rfc_8628               boolean,
    myproxyusername           clob,
    nonce                     clob,
    proxy_id                  clob,
    refresh_token             VARCHAR(255),
    refresh_token_expires_at  bigint,
    refresh_token_lifetime    bigint,
    refresh_token_valid       boolean,
    req_state                 clob,
    rt_jwt                    clob,
    scopes                    clob,
    states                    clob,
    temp_token                VARCHAR(255) PRIMARY KEY,
    temp_token_valid          boolean,
    user_code                 clob,
    username                  clob,
    validated_scopes          clob,
    verifier_token            varchar(255)
);

CREATE INDEX access_token on oauth2.transactions (access_token);
CREATE INDEX refresh_token on oauth2.transactions (refresh_token);

CREATE TABLE oauth2.client_approvals
(
   approval_ts                timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   approved                   boolean,
   approver                   clob,
   client_id                  VARCHAR(255) PRIMARY KEY,
   description                clob,
   status                     clob
);

CREATE TABLE oauth2.adminClients
(
   admin_id                    VARCHAR(255) PRIMARY KEY,
   allow_custom_ids            boolean,
   allow_qdl                   boolean,
   config                      clob,
   creation_ts                 timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   debug_on                    boolean,
   description                 clob,
   email                       clob,
   generate_ids                boolean,
   id_start                    clob,
   issuer                      clob,
   jwks                        clob,
   kid                         clob,
   last_accessed               bigint,
   last_modified_ts            timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   list_users                  boolean,
   list_users_other_clients    boolean,
   max_clients                 bigint,
   name                        clob,
   new_client_notify           boolean,
   secret                      clob,
   use_timestamps_in_ids       boolean,
   vo                          clob,
   vo_uri                      clob
);

CREATE TABLE oauth2.clients
(
   at_lifetime               bigint,
   at_max_lifetime           bigint,
   audience                  clob,
   callback_uri              clob,
   cfg                       clob,
   client_id                 VARCHAR(255) PRIMARY KEY,
   creation_ts               timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   debug_on                  boolean,
   description               clob,
   df_interval               bigint,
   df_lifetime               bigint,
   email                     clob,
   error_url                 clob,
   ersatz_client             boolean,
   ersatz_inherit_id_token   boolean,
   extended_attributes       clob,
   extends_provisioners      boolean,
   forward_scopes_to_proxy   boolean,
   home_url                  clob,
   idt_lifetime              bigint,
   idt_max_lifetime          bigint,
   issuer                    clob,
   jwks                      clob,
   kid                       clob,
   last_accessed             bigint,
   last_modified_ts          timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   ldap                      clob,
   name                      clob,
   prototypes                clob,
   proxy_claims_list         clob,
   proxy_limited             boolean,
   proxy_request_scopes      clob,
   public_client             boolean,
   public_key                clob,
   rfc7523_client            boolean,
   rfc7523_client_users      clob,
   rt_grace_period           bigint,
   rt_lifetime               bigint,
   rt_max_lifetime           bigint,
   scopes                    clob,
   sign_tokens               boolean,
   skip_server_scripts       boolean,
   strict_scopes             boolean
   );

CREATE TABLE oauth2.permissions
(
   admin_id                 VARCHAR(255),
   can_approve              boolean,
   can_create               boolean,
   can_read                 boolean,
   can_remove               boolean,
   can_substitute           boolean,
   can_write                boolean,
   client_id                VARCHAR(255),
   creation_ts              timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
   description              clob,
   ersatz_id                clob,
   permission_id            VARCHAR(255) PRIMARY KEY
);
CREATE INDEX p_client ON oauth2.permissions(client_id);

CREATE TABLE oauth2.tx_records
(
   audience            clob,
   description         clob,
   expires_at          bigint,
   issued_at           bigint,
   issuer              clob,
   lifetime            bigint,
   parent_id           VARCHAR(255),
   resource            clob,
   scopes              clob,
   state               clob,
   stored_token        clob,
   token_id            VARCHAR(255) PRIMARY KEY,
   token_type          clob,
   valid               boolean
);
CREATE INDEX  parents on oauth2.tx_records (parent_id);


CREATE TABLE oauth2.virtual_organizations
(
   at_issuer              clob,
   created                bigint,
   default_key_id         clob,
   description            clob,
   discovery_path         VARCHAR(255),
   issuer                 clob,
   json_web_keys          clob,
   last_accessed          bigint,
   last_modified          bigint,
   resource               clob,
   title                  clob,
   valid                  boolean,
   vo_id                  VARCHAR(255) PRIMARY KEY
);
create  INDEX discovery_path on oauth2.virtual_organizations (discovery_path);


















































/*
 Darned use command for mysql equivalent SHow Create Tables for Derby

describe oauth2.transactions

 */