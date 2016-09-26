/*
 Creates everything for the OA4MP = OAuth for MyProxy PostgreSQL client database.
 pipe it into postgres by issuing

 \i /path/to/postgres.sql

 in the psql client or just cut and paste it into the client directly.

 Edit the following values to be what you want. Be sure to update your configuration file.
 Note that passwords must have included escaped quotes, so place your password between the
 \' delimeters.

  A few very useful commands to issue in the psql client are
  \l - lists all databases
  \dn - lists all schemas in the current database
  \z tablename - lists permissions for the given table
  \d  - lists all tables in a database
  \d tablename - lists all columns in the given table
  \d+ tablename - lists a description of the table.


 */
\set oa4mpDatabase oauth
\set oa4mpSchema oauth
\set oa4mpAssetTable assets
\set oa4mpUser oa4mp
\set oa4mpUserPassword '\'setpassword\''

/*
  Nothing needs to be edited from here down, unless you have a very specific reason to do so.
 */
DROP SCHEMA IF EXISTS :oa4mpSchema CASCADE;
DROP DATABASE IF EXISTS :oa4mpDatabase;
DROP USER IF EXISTS :oa4mpUser;

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

CREATE USER :oa4mpUser with PASSWORD :oa4mpUserPassword;


create table :oa4mpSchema.:oa4mpAssetTable  (
    identifier  text PRIMARY KEY,
    redirect_uri text,
    username text,
    private_key text,
    certificate text,
    cert_req text,
    access_token text,
    refresh_token text,
    nonce text,
    issuedat TIMESTAMP,
    state text,
    refresh_lifetime bigint,
    token text,
    creation_ts TIMESTAMP);


/*
 Set permissions.
 Note that you may, depending on some other issues, have to grant privleges on the schema
 differently than below. Schema access is necessary or the users will still not be able to
 gain access to the tables. i.e. you can
 grant privileges to the table but still not be able to access things through the schema.
*/
GRANT ALL PRIVILEGES ON SCHEMA :oa4mpSchema TO :oa4mpUser;

GRANT ALL PRIVILEGES ON :oa4mpSchema.:oa4mpAssetTable TO :oa4mpUser;

commit;
