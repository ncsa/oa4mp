if [ ! -d "$NCSA_DEV_INPUT/oa4mp" ]
  then
    echo "No sources,  exiting.."
    exit 1
fi
cd "$NCSA_DEV_INPUT/oa4mp"
./build.sh
if [[ $? -ne 0 ]] ; then
    echo "could not build, see log"
    exit 1
fi
./build-tools.sh
if [[ $? -ne 0 ]] ; then
    echo "could not execute build-tools.sh"
    exit 1
fi