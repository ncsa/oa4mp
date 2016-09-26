# Creates everything for the XSEDE upser portal database. pipe it into mysql or just cut and paste it
# You must be logged in as root for this to work.

# First commands clean out the database and users.
# There are three uses who are in the specification Which is found currently at
# https://docs.google.com/document/d/1EuMq2JG_kjdr4Lloa3VJmW3Cc4cm7YQM8OG2V9pqizU/edit?hl=en_US
# A fourth user, tg-admin is included here to help with overall administration, though optional.
DROP DATABASE oauth;
DROP USER 'xup-admin'@'localhost';
DROP USER 'xup-portal'@'localhost';
DROP USER 'xup-approver'@'localhost';
DROP USER 'xup-client'@'localhost';

CREATE DATABASE oauth;
use oauth;

# Replace the phrase 'INSERT PASSWORD' with the acutal passwords for these accounts.
CREATE USER 'xup-admin'@'localhost' IDENTIFIED BY 'INSERT PASSWORD';
CREATE USER 'xup-portal'@'localhost' IDENTIFIED BY 'INSERT PASSWORD';
CREATE USER 'xup-approver'@'localhost' IDENTIFIED BY 'INSERT PASSWORD';
CREATE USER 'xup-client'@'localhost' IDENTIFIED BY 'INSERT PASSWORD';

# Set permissions. There is an admin user name tg-admin to help with this.
GRANT ALL PRIVILEGES ON oauth.clients TO 'xup-admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON oauth.transactions TO 'xup-admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON oauth.client_approvals TO 'xup-admin'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON oauth.transactions TO 'xup-portal'@'localhost';
GRANT ALL PRIVILEGES ON oauth.client_approvals TO 'xup-approver'@'localhost';
GRANT ALL PRIVILEGES ON oauth.clients TO 'xup-client'@'localhost';

COMMIT;

# NOTE: In Mysql you cannot have a text field that is called the primary key. A primary key is
# just a unique index that is implicitly not null, so just we just create the keys that way, but limit them
# to the first 1000 characters.

create table oauth.clients  (
    oauth_consumer_key  text NOT NULL ,
    oauth_client_pubkey text,
    name text,
    home_url text,
    error_url text,
    email text,
    creation_ts TIMESTAMP,
    UNIQUE INDEX oc_key (oauth_consumer_key(1000))
    );

create table oauth.client_approvals(
    oauth_consumer_key text NOT NULL,
    approver text,
    approved boolean,
    approval_ts TIMESTAMP,
    CONSTRAINT Foreign key (oauth_consumer_key(1000)) REFERENCES oauth.clients (oauth_consumer_key)
    );

create table oauth.transactions (
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
   username text,
   Constraint Foreign key (oauth_consumer_key(1000)) references oauth.clients (oauth_consumer_key),
   UNIQUE INDEX (temp_token(1000)),
   UNIQUE INDEX (oauth_verifier(1000)),
   UNIQUE INDEX (access_token(1000))
   );

commit;
# Now to grant restricted access. The  tables have to exist before this step

GRANT SELECT ON oauth.client_approvals TO 'xup-client'@'localhost';
GRANT SELECT ON oauth.clients TO 'xup-approver'@'localhost';
GRANT SELECT ON oauth.client_approvals TO 'xup-portal'@'localhost';
GRANT SELECT ON oauth.clients TO 'xup-portal'@'localhost';

commit;