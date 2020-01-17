package edu.uiuc.ncsa.oa4mp;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/23/19 at  5:33 PM
 */
public class LdapConfig {
    /*
    {
            "ldap": {
              "preProcessing": [
                {
                  "$if": ["$true"],
                  "$then": [
                    {
                      "$set": [
                        "foo",
                        {
                          "$drop": [
                            "@ncsa.illinois.edu",
                            "${eppn}"
                          ]
                        }
                      ]
                    }
                  ]
                }
              ],
              "postProcessing": [
                {
                  "$if": ["$true"],
                  "$then": [
                    {"$exclude": ["foo"]},
                    {"$set": ["sub",{"$get": ["eppn"]}]}
                  ]
                },
                {
                  "$if": [
                    {"$not": [{"$isMemberOf": ["prj_sprout"]}]}
                  ],
                  "$then": [{"$accept_requests": ["$false"]}]
                }
              ],
              "id": "58a170bfe4a59c05",
              "name": "58a170bfe4a59c05",
              "address": "ldap.ncsa.illinois.edu",
              "port": 636,
              "enabled": true,
              "authorizationType": "none",
              "failOnError": false,
              "notifyOnFail": false,
              "searchAttributes": [
                {
                  "name": "mail",
                  "returnAsList": false,
                  "returnName": "email"
                },
                {
                  "name": "cn",
                  "returnAsList": false,
                  "returnName": "name"
                },
                {
                  "name": "memberOf",
                  "isGroup": true,
                  "returnAsList": false,
                  "returnName": "isMemberOf"
                }
              ],
              "searchBase": "ou=People,dc=ncsa,dc=illinois,dc=edu",
              "searchName": "foo",
              "contextName": "",
              "ssl": {
                "keystore": {},
                "tlsVersion": "TLS",
                "useJavaTrustStore": true,
                "password": "changeit",
                "type": "jks"
              }
            }
          }
     */
}
