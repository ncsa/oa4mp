create schema oauth;

-- Note that the max index key size < .5 * page size, defaults to 2048.
 -- To increase the size of the consumer key column, etc., you will have to
 -- specify the correct page size.

create table oauth.clients  (
    oauth_consumer_key  VARCHAR(2048) NOT NULL ,
    oauth_client_pubkey LONG VARCHAR,
    name LONG VARCHAR,
    home_url LONG VARCHAR,
    error_url LONG VARCHAR,
    email LONG VARCHAR,
    creation_ts TIMESTAMP,
    PRIMARY KEY (oauth_consumer_key)
    );

create table oauth.client_approvals(
    oauth_consumer_key varchar(2048) NOT NULL,
    approver LONG VARCHAR,
    approved boolean,
    approval_ts TIMESTAMP,
    PRIMARY KEY (oauth_consumer_key)
    );

create table oauth.transactions (
   temp_token VARCHAR(2048) NOT NULL,
   temp_token_valid boolean,
   oauth_callback LONG VARCHAR,
   certreq LONG VARCHAR,
   certlifetime bigint,
   oauth_consumer_key LONG VARCHAR,
   oauth_verifier VARCHAR(2048),
   access_token VARCHAR(2048),
   access_token_valid boolean,
   certificate LONG VARCHAR,
   username LONG VARCHAR,
   PRIMARY KEY (temp_token)
   );

CREATE UNIQUE INDEX vt_ndx ON oauth.transactions (oauth_verifier);
CREATE UNIQUE INDEX at_ndx ON oauth.transactions (access_token);

