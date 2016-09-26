/*
 Creates everything for the OA4MP = OAuth for MyProxy PostgreSQL server database.
 pipe it into postgres by issuing

 \i /path/to/pg.sql

 in the psql client or just cut and paste it into the client directly.

 Edit the following values to be what you want. Be sure to update your configuration file.
 Note that passwords must have included escaped quotes, so place your password between the
 \' delimeters.

 */
\set oa4mpDatabase oauth
\set oa4mpSchema oauth
\set oa4mpTransactionTable transactions
\set oa4mpClientTable clients
\set oa4mpApproverTable client_approvals
\set oa4mpServerUser oa4mp_server
\set oa4mpServerUserPassword '\'setpassword\''
\set oa4mpApproverUser oa4mp_approver
\set oa4mpApproverUserPassword '\'setpassword\''
\set oa4mpClientUser oa4mp_client
\set oa4mpClientUserPassword '\'setpassword\''

/*
  Nothing needs to be edited from here down, unless you have a very specific reason to do so.
 */
DROP SCHEMA IF EXISTS :oa4mpSchema CASCADE;
DROP DATABASE IF EXISTS :oa4mpDatabase;
DROP USER IF EXISTS :oa4mpServerUser;
DROP USER IF EXISTS :oa4mpApproverUser;
DROP USER IF EXISTS :oa4mpClientUser;

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
CREATE USER :oa4mpApproverUser WITH PASSWORD :oa4mpApproverUserPassword;
CREATE USER :oa4mpClientUser with PASSWORD :oa4mpClientUserPassword;



create table :oa4mpSchema.:oa4mpClientTable  (
    oauth_consumer_key  text PRIMARY KEY,
    oauth_client_pubkey text,
    name text,
    home_url text,
    error_url text,
    email text,
    proxy_limited boolean,
    creation_ts TIMESTAMP);

CREATE UNIQUE INDEX client_ndx ON :oa4mpSchema.:oa4mpClientTable (oauth_consumer_key);

create table :oa4mpSchema.:oa4mpApproverTable(
    oauth_consumer_key text,
    approver text,
    approved boolean,
    approval_ts TIMESTAMP);

create table :oa4mpSchema.:oa4mpTransactionTable  (
   temp_token text NOT NULL,
   temp_token_valid boolean,
   oauth_callback text,
   certreq text,
   certlifetime bigint,
   oauth_consumer_key text,
   oauth_verifier text,
   access_token text,
   access_token_valid boolean,
   certificate text,
   username text);

CREATE UNIQUE INDEX trans_ndx ON :oa4mpSchema.:oa4mpTransactionTable (temp_token, oauth_verifier, access_token);

/*
 Set permissions. There is an admin user name oa4mp-admin to help with this.
 Note that you may, depending on some other issues, have to grant privleges on the schema
 differently than below. Schema access is necessary or the users will still not be able to 
 gain access to the tables. i.e. you can
 grant privileges to the table but still not be able to access things through the schema.
*/
GRANT ALL PRIVILEGES ON SCHEMA :oa4mpSchema TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON SCHEMA :oa4mpSchema TO :oa4mpApproverUser;
GRANT ALL PRIVILEGES ON SCHEMA :oa4mpSchema TO :oa4mpClientUser;

GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpTransactionTable TO :oa4mpServerUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpApproverTable  TO :oa4mpApproverUser;
GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpClientTable TO :oa4mpClientUser;


/*
 Now to grant restricted access. The  tables have to exist before this step
*/
GRANT SELECT ON :oa4mpSchema.:oa4mpApproverTable TO :oa4mpClientUser;
GRANT SELECT ON :oa4mpSchema.:oa4mpClientTable TO :oa4mpApproverUser;
GRANT SELECT ON :oa4mpSchema.:oa4mpApproverTable TO :oa4mpServerUser ;
GRANT SELECT ON :oa4mpSchema.:oa4mpClientTable TO :oa4mpServerUser;

commit;

/*
  A few very useful commands to issue in the psql client are
  \l - lists all databases
  \dn - lists all schemas in the current database
  \z tablename - lists permissions for the given table
  \d  - lists all tables in a database
  \d tablename - lists all columns in the given table
  \d+ tablename - lists a description of the table.
*/