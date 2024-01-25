package edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/5/15 at  2:28 PM
 */
public interface OA2Claims {
    public static String ISSUER = "iss";
    /**
     * Subject - Identifier for the End-User at the Issuer.
     */
    public static String SUBJECT = "sub";
    public static String AUDIENCE = "aud";
    public static String AUTHORIZED_PARTY = "azp";
    public static String RESOURCE = "resource"; // RFC8707
    public static String EXPIRATION = "exp";
    public static String ISSUED_AT = "iat";
    public static String NOT_VALID_BEFORE = "nbf";
    public static final String JWT_ID = "jti";
    public static final String AUTH_TIME = "auth_time";


    String IDP = "idp";
    String IDP_NAME = "idp_name";
    String EPPN = "eppn";
    String EPTID = "eptid";
    String EDU_PERSON_ASSURANCE = "eduPersonAssurance";
    String EDU_PERSON_ORCID = "eduPersonOrcid";
    String OPENID = "openid";
    String OIDC = "oidc";
    String PAIRWISE_ID = "pairwise_id";
    String SUBJECT_ID = "subject_id";
    String I_TRUST_UIN = "itrustuin";
    String UID_NUMBER = "uidNumber";
    String UID = "uid";

    String OU = "ou";
    String AFFILIATION = "affiliation";
    String ENTITLEMENT = "entitlement";
    String CERT_SUBJECT_DN = "cert_subject_dn";
    String AUTHENTICATION_CLASS_REFERENCE = "acr";
    String AUTHENTICATION_METHOD_REFERENCE = "amr";
    /*
    The next few can be attributes that are returned from LDAP (cn = common name,
    dn = domain name sn = simple(?) name. 
     */
    String LDAP_DN = "dn";
    String LDAP_CN = "cn";
    String LDAP_SN = "sn";


    /**
     * OA4MP specific claim for group memberships that may come from e.g. LDAP.
     */
    public static String IS_MEMBER_OF = "isMemberOf";
    public static String VO_PERSON_ID = "voPersonID";
    public static String EDU_PERSON_ENTITLEMENT = "eduPersonEntitlement";
    public static String VO_PERSON_EXTERNALID = "voPersonExternalID";


    /**
     * End-User's full name in displayable form including all name parts, possibly including titles and
     * suffixes, ordered according to the End-User's locale and preferences.
     */
    public static String NAME = "name";
    /**
     * Given name(s) or first name(s) of the End-User. Note that in some cultures, people can have
     * multiple given names; all can be present, with the names being separated by space characters.
     */
    public static String GIVEN_NAME = "given_name";
    /**
     * Surname(s) or last name(s) of the End-User. Note that in some cultures, people can have multiple family names
     * or no family name; all can be present, with the names being separated by space characters.
     */
    public static String FAMILY_NAME = "family_name";
    /**
     * Middle name(s) of the End-User. Note that in some cultures, people can have multiple middle names;
     * all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
     */
    public static String MIDDLE_NAME = "middle_name";
    /**
     * Casual name of the End-User that may or may not be the same as the given_name. For instance, a
     * nickname value of Mike might be returned alongside a given_name value of Michael.
     */
    public static String NICKNAME = "nickname";
    /**
     * Shorthand name by which the End-User wishes to be referred to at the RP, such as
     * janedoe or j.doe. This value MAY be any valid JSON string including special characters such as @, /, or whitespace. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     */
    public static String PREFERRED_USERNAME = "preferred_username";
    /**
     * Also found is the name used in addressing the user directly, in e.g. dialog
     * boxes. This may be required in various places (such as non-Western or florid Hispanic)
     * names where it is unclear what to use. Typically the user sets this in some configuration
     * when they register for their IDP and we simply pass it back.
     */
    public static String DISPLAY_NAME = "display_name";
    /**
     * URL of the End-User's profile page. The contents of this Web page SHOULD be
     * about the End-User.
     */
    public static String PROFILE = "profile";
    /**
     * URL of the End-User's profile picture. This URL MUST refer to an image file (for example, a PNG, JPEG, or GIF image file), rather than to a Web page containing an image. Note that this URL SHOULD specifically reference a profile photo of the
     * End-User suitable for displaying when describing the End-User, rather than an arbitrary photo taken by the End-User.
     */
    public static String PICTURE = "picture";
    /**
     * URL of the End-User's Web page or blog. This Web page SHOULD contain information published by
     * the End-User or an organization that the End-User is affiliated with.
     */
    public static String WEBSITE = "website";
    /**
     * End-User's preferred e-mail address. Its value MUST conform to
     * the RFC 5322 [RFC5322] addr-spec syntax. The RP MUST NOT rely upon this value being unique, as discussed in Section 5.7.
     */
    public static String EMAIL = "email";
    /**
     * True if the End-User's e-mail address has been verified; otherwise false. When this Claim FunctorType is true, this means that the OP took affirmative steps to ensure that this e-mail address was controlled by the End-User at the time the verification was performed. The means by which an e-mail address is verified is context-specific, and dependent
     * upon the trust framework or contractual agreements within which the parties are operating.
     */
    public static String EMAIL_VERIFIED = "email_verified";
    /**
     * End-User's gender. Values defined by this specification are female and male.
     * Other values MAY be used when neither of the defined values are applicable.
     */
    public static String GENDER = "gender";
    /**
     * End-User's birthday, represented as an ISO 8601:2004 [ISO8601‑2004] YYYY-MM-DD format. The year MAY be 0000, indicating that it is omitted. To represent only the year, YYYY format is allowed. Note that depending on the underlying platform's date related function, providing just year can result in varying month
     * and day, so the implementers need to take this factor into account to correctly process the dates.
     */
    public static String BIRTHDATE = "birthdate";
    /**
     * String from zoneinfo [zoneinfo] time zone database representing the
     * End-User's time zone. For example, Europe/Paris or America/Los_Angeles.
     */
    public static String ZONEINFO = "zoneinfo";
    /**
     * End-User's locale, represented as a BCP47 [RFC5646] language tag. This is typically an ISO 639-1 Alpha-2 [ISO639‑1] language code in lowercase and an ISO 3166-1 Alpha-2 [ISO3166‑1] country code in uppercase, separated by a dash. For example, en-US or fr-CA. As a compatibility note, some implementations have used an underscore
     * as the separator rather than a dash, for example, en_US; Relying Parties MAY choose to accept this locale syntax as well.
     */
    public static String LOCALE = "locale";
    /**
     * End-User's preferred telephone number. E.164 [E.164] is RECOMMENDED as the format of this Claim, for example, +1 (425) 555-1212 or +56 (2) 687 2400. If the phone number contains an extension, it is RECOMMENDED that the
     * extension be represented using the RFC 3966 [RFC3966] extension syntax, for example, +1 (604) 555-1234;ext=5678.
     */
    public static String PHONE_NUMBER = "phone_number";
    /**
     * True if the End-User's phone number has been verified; otherwise false. When this Claim FunctorType is true, this means that the OP took affirmative steps to ensure that this phone number was controlled by the End-User at the time the verification was performed. The means by which a phone number is verified is context-specific, and dependent upon the trust framework or contractual agreements within which the parties are operating. When true, the phone_number Claim MUST be in
     * E.164 format and any extensions MUST be represented in RFC 3966 format.
     */
    public static String PHONE_NUMBER_VERIFIED = "phone_number_verified";
    /**
     * End-User's preferred postal address. The value of the address member is a JSON [RFC4627] structure
     * containing some or all of the members defined in Section 5.1.1.
     */
    public static String ADDRESS = "address";
    /**
     * Time the End-User's information was last updated. Its value is a JSON number representing
     * the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the date/time
     */
    public static String UPDATED_AT = "updated_at";
    String[] USER_INFO_CLAIMS = new String[]{AFFILIATION,CERT_SUBJECT_DN,ENTITLEMENT,
            EPPN,EPTID,EDU_PERSON_ASSURANCE,EDU_PERSON_ENTITLEMENT,EDU_PERSON_ORCID,IDP,IDP_NAME,
            IS_MEMBER_OF,I_TRUST_UIN,OIDC,OPENID,OU,PAIRWISE_ID,SUBJECT_ID,
            UID_NUMBER,VO_PERSON_EXTERNALID,VO_PERSON_ID, LDAP_CN, LDAP_DN, LDAP_SN};
}
