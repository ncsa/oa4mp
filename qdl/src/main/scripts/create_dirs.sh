# Create the directory structure for OA4MP's QDL distro. This assumes that QDL sources
# are installed and you have built QDL. It will then use the scripts in the QDL
# distro to create the correct directory structure and populate it. Arguments are
#
# 1st - the root directory of the QDL install
# 2nd - the output directory of this script, which will be jarred up
#       and used by the installer to create it on the user's drive
#
# they default to values set with the envrionment variables
#
# NCSA_DEV_INPUT
# NCSA_DEV_OUTPUT
#
# So if those are set, you don't need to send arguments.

DEFAULT_QDL_ROOT=$NCSA_DEV_INPUT/qdl
DEFAULT_OA4MP_QDL_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp-qdl
OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp


QDL_ROOT=${1:-$DEFAULT_QDL_ROOT}
OA4MP_QDL_DEPLOY=${2:-$DEFAULT_OA4MP_QDL_DEPLOY}

# First off is to run the actual QDL build to get the directories created
# with the documentation, QDL native modules etc. These have to be part of a distro

cd $QDL_ROOT/language/src/main/scripts || exit
./create_dirs.sh $QDL_ROOT $OA4MP_QDL_DEPLOY
# Now that there is a place, put the OA4MP specific documents in the docs directory
$OA4MP_ROOT/website/convert-docs.sh  $OA4MP_ROOT $OA4MP_QDL_DEPLOY/docs


