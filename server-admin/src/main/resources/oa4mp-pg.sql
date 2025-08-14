/*
 Creates everything for the OA4MP = OAuth for MyProxy PostgreSQL server database.
 AFTER YOU HAVE (at the least) EDITED THE PASSWORD BELOW, pipe it into postgres by issuing

 \i /path/to/oa4mp-pg.sql

 in the psql client or just cut and paste it into the client directly.

 Be sure to update your configuration file.
 Note that passwords must have included escaped quotes, so place your password between the
 \' delimeters.

 */
\set oa4mpServerUser oa4mp
\set oa4mpServerUserPassword '\'Password\''

/* Probably don't have to change anything from here on down... */
\set oa4mpDatabase oa4mp
\set oa4mpSchema oa4mp
\set oa4mpTransactionTable transactions
\set oa4mpClientTable clients
\set oa4mpClientCallbackTable callbacks
\set oa4mpApproverTable client_approvals
\set oa4mpAdminClientTable adminClients
\set oa4mpPermissionsTable permissions


/*
  Nothing needs to be edited from here down, unless you have a very specific reason to do so.
 */
DROP SCHEMA IF EXISTS :oa4mpSchema CASCADE;
DROP DATABASE IF EXISTS :oa4mpDatabase;
DROP USER IF EXISTS :oa4mpServerUser;

/* 
  Schemas live in databases, so create the database then the schema.
  Note that you have to switch to use the database after you create it 
  or you will not create the schema in the right place
  and get a "schema not found" exception. 
*/
CREATE DATABASE :oa4mpDatabase;
\c :oa4mpDatabase
CREATE SCHEMA :oa4mpSchema;
set search_path to :oa4mpSchema;

CREATE USER :oa4mpServerUser with PASSWORD :oa4mpServerUserPassword;

create table :oa4mpSchema.:oa4mpClientTable  (
          client_id           text PRIMARY KEY,
          public_key          text,
          name                text,
          home_url            text,
          error_url           text,
          email               text,
          callback_uri        text,
          proxy_limited       boolean,
ersatz_inherit_id_token       boolean,
          rt_lifetime         bigint,
          last_modified_ts    TIMESTAMP,
          creation_ts         TIMESTAMP,
          issuer              text,
          ldap                text,
          scopes              text,
          proxy_claims_list   text,
          public_client       boolean,
          sign_tokens         boolean,
          cfg                 text,
          extended_attributes text);

create table :oa4mpSchema.:oa4mpPermissionsTable  (
 permission_id text PRIMARY KEY,
  admin_id      text,
  client_id     text,
  can_approve   BOOLEAN,
  can_create    BOOLEAN,
  can_read      BOOLEAN,
  can_remove    BOOLEAN,
  can_write     BOOLEAN,
  creation_ts   TIMESTAMP
  );
create table :oa4mpSchema.:oa4mpAdminClientTable  (
                 admin_id    text PRIMARY KEY,
                 name        text,
                 email       text,
                 secret      text,
                 vo          text,
    list_users_other_clients boolean,
                 initialize_flows            boolean,
                  list_users boolean,
                  vo_uri     text,
                 rfc7523_client              boolean,
                 rfc7523_client_users        text,
                 issuer     text,
                  max_clients integer,
    creation_ts TIMESTAMP);



create table :oa4mpSchema.:oa4mpApproverTable(
    client_id   text primary key,
    approver    text,
    status      text,
    approved    boolean,
    approval_ts TIMESTAMP);

CREATE TABLE :oa4mpSchema.tx_records
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
    resource   text
);

create table :oa4mpSchema.:oa4mpTransactionTable  (
   temp_token           text primary key,
   temp_token_valid     boolean,
   callback_uri         text,
   certreq              text,
   certlifetime         bigint,
   client_id            text,
   consent_page_ok      boolean,
   verifier_token       text,
   access_token         text,
   access_token_valid   boolean,
   states               text,
   certificate          text,
   refresh_token        text,
   refresh_token_valid  boolean,
   expires_in           bigint,
   myproxyusername      text,
   PROXY_ID             text,
   at_lifetime          bigint,
   username             text,
   auth_time            TIMESTAMP DEFAULT now(),
   nonce                text,
   scopes               text);

CREATE UNIQUE INDEX trans_ndx ON :oa4mpSchema.:oa4mpTransactionTable (temp_token, refresh_token, access_token, username);

/*
 Set permissions. There is an admin user name oa4mp-admin to help with this.
 Note that you may, depending on some other issues, have to grant privileges on the schema
 differently than below. Schema access is necessary or the users will still not be able to 
 gain access to the tables. i.e. you can
 grant privileges to the table but still not be able to access things through the schema.
*/
GRANT ALL PRIVILEGES ON SCHEMA :oa4mpSchema TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpTransactionTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpApproverTable  TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpClientTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpClientCallbackTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpAdminClientTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpPermissionsTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpLDAPTable TO :oa4mpServerUser;

commit;

/*
  A few very useful commands to issue in the psql client are
  \l - lists all databases
  \dn - lists all schemas in the current database
  \z tablename - lists permissions for the given table
  \d  - lists all tables in a database
  \d tablename - lists all columns in the given table
  \d+ tablename - lists a description of the table.

  E.g.
  \c oauth2;
  \dn <-- lists all schemas
  set search_path to oauth2; <-- or no meta commands work right
  \d <-- lists the tables
  \d tablename <-- shows all columns and their types. Almost show create table

  select * from sys.syscolumns where referenceid = (select tableid from sys.systables where tablename = 'ciloa2.clients') order by columnnumber

  select ciloa2.clients  from sys.systables st LEFT OUTER join sys.sysschemas ss on (st.schemaid = ss.schemaid) where ss.schemaname ='ciloa2';

  select clients  from sys.systables st LEFT OUTER join sys.sysschemas ss on (st.schemaid = ss.schemaid) where ss.schemaname ='ciloa2';


*/