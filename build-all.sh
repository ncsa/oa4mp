if [ ! -d "$NCSA_DEV_INPUT/oa4mp" ]
  then
    echo "No sources,  exiting.."
    exit 1
fi
cd "$NCSA_DEV_INPUT/oa4mp"
./build.sh
./build-tools.sh