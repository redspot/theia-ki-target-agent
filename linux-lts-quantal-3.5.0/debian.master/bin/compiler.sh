if [ "x${WRAP_CMD}" == "x" ]; then
	exit 1
fi
if [ -z "${WRAP_PREFIX}" ]; then
    WRAP_PREFIX=/home/linuxbrew/.linuxbrew/bin/
fi
if [ -z "${WRAP_VERSION}" ]; then
    WRAP_VERSION=-4.9
fi
if [ -z "${WRAP}" ]; then
    WRAP="${WRAP_PREFIX}${WRAP_CMD}${WRAP_VERSION}"
fi

compiler_list=("gcc" "g++" "c++")
for c in "${compiler_list[@]}"; do
    if [ "$WRAP_CMD" == "$c" ]; then
        if which ccache &> /dev/null; then
            WRAP="ccache $WRAP"
        fi
        if which distcc &> /dev/null; then
            CCACHE_PREFIX="distcc"
            #DISTCC_HOSTS=...
            #edit ~/.distcc/hosts
        fi
        break;
    fi
done
