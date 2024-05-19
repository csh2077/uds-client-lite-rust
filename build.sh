#!/bin/bash

PLATFORM=${1:-all}

OUTPUT_DIR="output"

SCRIPT_PATH=$(dirname $(readlink -f $0))

echo "The target OS is: $PLATFORM"

# if [ -d "$OUTPUT_DIR" ]; then
#   rm -rf $OUTPUT_DIR
# fi

mkdir -p "${OUTPUT_DIR}"

compile_linux_ver() {
    echo "Running linux commands"
    LINUX_OUTPUT="$SCRIPT_PATH/$OUTPUT_DIR/uds_client_lite_rust_linux"
    if [ -f "$LINUX_OUTPUT" ]; then
        # echo "rm $LINUX_OUTPUT"
        rm $LINUX_OUTPUT
    fi
    cargo build --release
    mv $SCRIPT_PATH/target/release/uds_client_lite_rust $LINUX_OUTPUT
}

compile_win_ver() {
    echo "Running win commands"
    WIN_OUTPUT="$SCRIPT_PATH/$OUTPUT_DIR/uds_client_lite_rust_win.exe"
    if [ -f "$WIN_OUTPUT" ]; then
        # echo "rm $WIN_OUTPUT"
        rm $WIN_OUTPUT
    fi
    cargo build --target x86_64-pc-windows-gnu --release 
    mv $SCRIPT_PATH/target/x86_64-pc-windows-gnu/release/uds_client_lite_rust.exe $WIN_OUTPUT
}

case $PLATFORM in
    linux)
        compile_linux_ver
        ;;

    win)
        compile_win_ver
        ;;

    all)
        compile_linux_ver
        compile_win_ver
        ;;
    
    *)
        echo "Invalid platform! Please specify either 'linux', 'win' or 'all'."
        exit 1
        ;;
esac

