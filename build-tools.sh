# This will build all the tools for the local environment and deploy them,
# You must have the QDL source checked out to $NCSA_DEV_INPUT/qdl
# If you have local installs of QDL and OA4MP, this will update them.
#
# The normal lifecycle is to invoke build.sh from this directory, then
# if you want the tools, invoke this. Nothign will run unless try {
# detects various environment variables:
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
OA4MP_SERVER_DEPLOY=$NCSA_DEV_OUTPUT/server
OA4MP_QDL_DEPLOY=$NCSA_DEV_OUTPUT/oa4mp-qdl

if [ ! -d "$OA4MP_QDL_DEPLOY" ]; then
   mkdir "$OA4MP_QDL_DEPLOY"
   else
     echo "$OA4MP_QDL_DEPLOY" exists
fi
# next line is so the profiles for the tools can be found in the source and built.

cd $OA4MP_ROOT/qdl
mvn -P qdl package
mv target/oa2-qdl-jar-with-dependencies.jar target/qdl.jar

# If the user has the sources to QDL, build the installer.
# /home/ncsa/dev/ncsa-git/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $DEPLOY_ROOT/oa2-qdl oa2-qdl-installer.jar

#if [ -d "$NCSA_DEV_INPUT/qdl" ]; then
#   $NCSA_DEV_INPUT/qdl/language/src/main/scripts/create_installer.sh $OA4MP_ROOT/qdl $OA4MP_QDL_DEPLOY oa2-qdl-installer.jar
#else
#   echo "No QDL sources, creating OA4MP-QDL installer skipped."
#fi

# Update local QDL install with the latest and greatest
#
if [ -z ${QDL_HOME+x} ];  then
    echo "no QDL install, skipping..."
  else
  # If there is a local QDL install, update it.
    cp target/qdl.jar $QDL_HOME/lib;
    cp /home/ncsa/dev/temp-deploy/oa2-qdl/lib/build-info.txt $QDL_HOME/lib ;
fi

if [ -z ${OA4MP_HOME+x} ];  then
     echo "no OA4MP local install, skipping..."
  else
    # OA4MP client and cli deploy to local system
    cd $OA4MP_SERVER_DEPLOY
    cp cli.jar $OA4MP_HOME/lib
    cp clc.jar $OA4MP_HOME/lib
fi

