/*
   This comment section tells how to set up an Apache Derby database to
   work with OA4MP.

   Create the directory to where you want derby to create the database.
   This directory should be empty, since Derby will create everything on your
   behalf -- and might refuse to do anything if the directory has content.
   Make the following substitutions below:

         DB_NAME - the entire path to this database,
     DB_PASSWORD - password to the database
       USER_NAME - name of the user (created below)
   USER_PASSWORD - password for user
          SCHEMA - schema for the database

   Note 1: If you want your database to live in

       /opt/oauth2/var/derby/oa4mp

   you would create

      /opt/oauth2/var/derby

   with nothing in it and the DB_NAME is then

      /opt/oauth2/var/derby/oa4mp

   I.e., the last directory in this path is what Derby creates.

   Note 2: In Derby, the database lives in a directory. This means that unless
   certain precautions are taken, it is completely insecure. The setup below
   mitigates this.

   1. Puts a password on the entire database so it cannot be read from the disk
   2. Sets a user and password to access the database.
      These are stored in the database, hence step 1 to lock the whole thing down.
   3. All database access from OA4MP is via the so-called embedded driver, so
      no network traffic is needed.

   One-time install instructions
   ----------------------------
   Install derby, probably with a package manager like synaptic or yum.
   Note that outdented lines are to be pasted into the command line

   Start derby with

ij

   Then issue the following. This sets up the database and will create the user above
   (Note that the user name and password are set as properties, so do substitute).
   Even though the user does not exist yet, you must  connect with the
   user name so that they are the owner of the database.

connect 'jdbc:derby:DB_NAME;create=true;dataEncryption=true;bootPassword=DB_PASSWORD;user=USER_NAME';
call syscs_util.syscs_set_database_property('derby.connection.requireAuthentication', 'true');
call syscs_util.syscs_set_database_property('derby.authentication.provider', 'BUILTIN');
call syscs_util.syscs_set_database_property('derby.user.USER_NAME', 'USER_PASSWORD');
call syscs_util.syscs_set_database_property('derby.database.propertiesOnly', 'true');
call syscs_util.syscs_set_database_property('derby.database.sqlAuthorization', 'true');

   Optional test:
   If you want be sure it works, create the schema as follows:

create schema oauth2;
show schemas;

   And a bunch of schemas will be displayed, including oauth2. This means everything
   worked. You don't need to issue the create schema command below.

   At this point, exit Derby. Initial setup is done. You must connect again as the user
   that runs this because creating the tables below will automatically assign the
   current user as the table owner, so no other permissions (which can get complicated)
   are needed.

exit;

   Now connect to it with the following from the command line after restarting ij:

connect 'jdbc:derby:DB_NAME;user=USER_NAME;password=USER_PASSWORD;bootPassword=DB_PASSWORD';

   and either paste in the rest of this file OR just run the whole thing from inside ij

run '/full/path/to/oauth2-derby.qdl';

   At this point, your database is ready for use.


*/

/* Uncomment this if you did not do the test above and have already created the schema.
CREATE SCHEMA oauth2;
*/

alter table oauth2.tx_records add column description CLOB;

CREATE TABLE oauth2.adminClients
(
    admin_id VARCHAR(255) PRIMARY KEY,
    name CLOB,
    secret CLOB,
    email CLOB,
    creation_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_modified_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    vo CLOB,
    list_users_other_clients boolean,
    list_users boolean,
    max_clients BIGINT,
    issuer CLOB,
    config CLOB
);

CREATE TABLE oauth2.clients
(
       client_id VARCHAR(255) PRIMARY KEY,
                    cfg CLOB,
                   ldap CLOB,
                   name CLOB,
                  email CLOB,
                 issuer CLOB,
                 scopes CLOB,
               audience CLOB,
               debug_on BOOLEAN,
               home_url CLOB,
              error_url CLOB,
             prototypes CLOB,
             public_key CLOB,
            antecessors CLOB,
            at_lifetime bigint,
            client_type INT,
            creation_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
            description CLOB,
            df_interval bigint,
            df_lifetime bigint,
            rt_lifetime bigint,
            sign_tokens BOOLEAN,
           callback_uri CLOB,
           proxy_claims CLOB,
          ersatz_client BOOLEAN,
          maxATLifetime bigint,
          maxRTLifetime bigint,
          proxy_limited BOOLEAN,
          public_client BOOLEAN,
          strict_scopes BOOLEAN,
        at_max_Lifetime bigint,
        rt_max_Lifetime bigint,
       last_modified_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      proxy_claims_list CLOB,
    extended_attributes CLOB,
    skip_server_scripts BOOLEAN,
   extends_provisioners BOOLEAN,
   proxy_request_scopes CLOB,
forward_scopes_to_proxy BOOLEAN
);



CREATE TABLE oauth2.permissions
(
    permission_id VARCHAR(255) PRIMARY KEY,
       admin_id VARCHAR(255),
      client_id VARCHAR(255),
    can_approve BOOLEAN,
     can_create BOOLEAN,
       can_read BOOLEAN,
     can_remove BOOLEAN,
      can_write BOOLEAN,
    creation_ts TIMESTAMP
);

CREATE TABLE oauth2.client_approvals
(
      client_id VARCHAR(255) PRIMARY KEY,
       approver CLOB,
       approved BOOLEAN,
         status CLOB,
    approval_ts TIMESTAMP
);


CREATE TABLE oauth2.transactions
(
                temp_token VARCHAR(255) PRIMARY KEY,
          temp_token_valid BOOLEAN,
              callback_uri CLOB,
                   certreq CLOB,
              certlifetime BIGINT,
                 client_id CLOB,
            verifier_token VARCHAR(1024),
              access_token VARCHAR(1024),
             refresh_token VARCHAR(1024),
       refresh_token_valid BOOLEAN,
                expires_in BIGINT,
                    states CLOB,
                  proxy_id CLOB,
               certificate CLOB,
                  username VARCHAR(8192),
           myproxyUsername CLOB,
        access_token_valid BOOLEAN DEFAULT NULL,
                 auth_time timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
                     nonce CLOB,
                    scopes CLOB,
                auth_grant varchar(1024),
    refresh_token_lifetime BIGINT,
      authz_grant_lifetime BIGINT,
                 req_state CLOB,
               is_rfc_8628 BOOLEAN,
                 user_code VARCHAR(1024)
);
   CREATE INDEX access_token on oauth2.transactions (access_token);
   CREATE INDEX refresh_token on oauth2.transactions (refresh_token);

CREATE TABLE oauth2.tx_records
(
      token_id VARCHAR(255) PRIMARY KEY,
      lifetime bigint,
     issued_at bigint,
    expires_at bigint,
     parent_id VARCHAR(1024),
    token_type CLOB,
         valid boolean,
        scopes CLOB,
      audience CLOB,
        issuer CLOB,
      resource CLOB);
   CREATE INDEX  parents on oauth2.tx_records (parent_id);


CREATE TABLE oauth2.virtual_organizations
(
             vo_id VARCHAR(255) PRIMARY KEY,
           created bigint,
    default_key_id CLOB,
    discovery_path VARCHAR(1024),
            issuer CLOB,
         at_issuer CLOB,
     json_web_keys CLOB,
     last_modified bigint,
             title CLOB,
          resource CLOB,
             valid boolean);
  create  INDEX discovery_path on oauth2.virtual_organizations (discovery_path);
