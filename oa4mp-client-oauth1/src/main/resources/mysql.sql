/*
   This script will create the tables for a basic oa4mp install. Since MySQL has *no* varaible
   support, everything is hard-coded. if you want something other than the default names and
   then edit the file. The only thing
*/
CREATE USER 'oa4mp-client'@'localhost' IDENTIFIED BY 'PASSWORD';

CREATE DATABASE oauth DEFAULT CHARACTER SET utf8;
use oauth;

# Set permissions. The permissions must be granted in MySQL before the tables are created.
GRANT ALL PRIVILEGES ON oauth.assets TO 'oa4mp-client'@'localhost';

COMMIT;

create table oauth.assets  (
        identifier  varchar(255) Primary key,
        private_key text,
        username text,
        redirect_uri text,
        certificate text,
        cert_req  text,
        token text,
        creation_ts TIMESTAMP
    );

commit;

