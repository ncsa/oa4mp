/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* variable
   support, everything is hard-coded. if you want something other than the default names and
   then edit the file. The only thing
*/
CREATE USER 'oa4mp-client'@'localhost' IDENTIFIED BY 'PASSWORD';

CREATE DATABASE oauth2 DEFAULT CHARACTER SET utf8;
use oauth2;

# Set permissions. The permissions must be granted in MySQL before the tables are created.
GRANT ALL PRIVILEGES ON oauth2.assets TO 'oa4mp-client'@'localhost';

COMMIT;

create table oauth2.assets  (
        identifier  varchar(255) Primary key,
        private_key text,
        username text,
        redirect_uri text,
        certificate text,
        refresh_token text,
        access_token text,
        nonce text,
        state text,
        issuedat timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        refresh_lifetime bigint,
        cert_req text,
        token text,
        creation_ts timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

commit;

