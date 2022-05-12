This directory contains the files for FNAL (FermiLab) clients. There are two sets of them

Both versions:
fnal/fnal-idtoken.qdl - for id token phase

For use with QDL before version 1.4
QDL 1.3.3 and lower:
fnal/fnal-at.qdl - for access tokens
fnal/wlcg_cs.qdl - utility for resolving WLCG groups

QDL 1.4 and above: These are not quite up to date with the more modern ones. The reason for the refactor
was that the old scripts were getting too large with too much scope creep. These
are more modular and should be used hencforth (from 7/12/2021 CILogon release 5.1.4):

    fnal/wlcg_groups.qdl - for resolving WLCG groups
            fnal/acl.qdl - Used for access control, list of allowed clients
     fnal/new/access.qdl - actual work for access tokens
         fnal/new/at.qdl - entry point (in client cfg) for token, refresh and exchange phase.
fnal/new/get_service.qdl - gets the service record (e.g. dunpro) from LDAP
   fnal/new/get_user.qdl - gets the user's record (e/g/ bob@fnal.gov) from LDAP
        fnal/new/rtx.qdl - actual processing of refresh and exchange phases.

There was a bug in versions of QDL before 1.4 that would not propagate the script args
quite faithfully in calls to other scripts. This meant that lots of little scripts wouldn't
work. The old scripts are written in such a way that this is not a problem, the
new scripts use the updated version of QDL.