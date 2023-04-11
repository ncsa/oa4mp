GA4GH version 2 as of 2021-10-05.  Differences are
 . new GA4GH version 2 scope.
. passports are returned in the access token on demand
. passports/visas are not returned from the user_info endpoint.
. RESTful calls to populate the passport

{"tokens": {"access": {
                      "lifetime": 1200000,
                      "qdl":  [
                         {
                        "load": "ga4gh/ga4gh.qdl",
                        "xmd": {"exec_phase": ["post_user_info"]}
                       },
                         {
                        "load": "ga4gh/at.qdl",
                        "xmd": {"exec_phase":    [
                         "post_token",
                         "post_refresh",
                         "post_exchange"
                        ]}
                       }
                      ],
                      "type": "scitoken"
                     }}}