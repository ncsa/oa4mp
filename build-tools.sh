# This will build all the tools for the local environment and deploy them,
# You must have the QDL source checked out to $NCSA_DEV_INPUT/qdl
# If you have local installs of QDL and OA4MP, this will update them.
#
# The normal lifecycle is to invoke build.sh from this directory, then
# if you want the tools, invoke this. Nothing will run unless it
# detects various environment variables:
# Generally this should be run after building QDL, though a planned improvement
# is to have it with its own installer.
# QDL_HOME
# OA4MP_HOME

# Next, go to the QDL extensions in OA4MP and build them.

if [ -z ${NCSA_DEV_INPUT+x} ];  then
    echo "no sources, skipping..."
    exit 1
fi

if [ -z ${NCSA_DEV_OUTPUT+x} ];  then
    echo "no output directory, skipping..."
    exit 1
fi

OA4MP_ROOT=$NCSA_DEV_INPUT/oa4mp
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp
OA4MP_QDL_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp-qdl

if [ ! -d "$OA4MP_QDL_DEPLOY" ]; then
   mkdir "$OA4MP_QDL_DEPLOY"
  # else
  #   echo "  QDL deploy directory exists"
fi
# next line is so the profiles for the tools can be found in the source and built.

#cd $OA4MP_ROOT/qdl
#mvn -P qdl package
#mv target/oa2-qdl-jar-with-dependencies.jar target/qdl.jar
#cp target/qdl.jar $OA4MP_QDL_DEPLOY

# If the user has the sources to QDL, build the installer.
# /home/ncsa/dev/ncsa-git/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $DEPLOY_ROOT/oa2-qdl oa2-qdl-installer.jar

#if [ -d "$NCSA_DEV_INPUT/qdl" ]; then
#   $NCSA_DEV_INPUT/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $OA4MP_QDL_DEPLOY oa2-qdl-installer.jar
#else
#   echo "No QDL sources, creating OA4MP-QDL installer skipped."
#fi

# Update local QDL install with the latest and greatest
#
cd "$OA4MP_ROOT/qdl/src/main/scripts"
echo "building OA4MP QDL installer"
./create_installer.sh
if [[ $? -ne 0 ]] ; then
    echo "OA4MP create installer failed"
    exit 1
fi

echo "deploying OA4MP QDL installer"


if [ -z ${QDL_HOME+x} ];  then
    echo "no QDL install, skipping..."
  else
  # If there is a local QDL install, update it.
    cp "$OA4MP_QDL_DEPLOY/lib/qdl.jar" $QDL_HOME/lib;
    cp "$OA4MP_QDL_DEPLOY/lib/build-info.txt" $QDL_HOME/lib ;
fi

if [ -z ${OA4MP_HOME+x} ];  then
     echo "no OA4MP local install, skipping..."
  else
    # OA4MP client and cli deploy to local system
    cd $OA4MP_SERVER_DEPLOY
    cp cli.jar $OA4MP_HOME/lib
    cp clc.jar $OA4MP_HOME/lib
fi
echo "     ... done!"

