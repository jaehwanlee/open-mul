# !/bin/bash

if [ -L $0 ] ; then
    cwd=$(readlink $0)
else
    cwd=$0
fi
curr_dir=$(dirname $cwd)


cd $curr_dir

function stop-command {
    sudo killall -9 mulcli > /dev/null 2>&1
    sudo killall -9 mull2sw > /dev/null 2>&1
    sudo killall -9 mulfab > /dev/null 2>&1
    sudo killall -9 multr > /dev/null 2>&1
    sudo killall -9 mul > /dev/null 2>&1
    sudo killall -9 lt-mulcli > /dev/null 2>&1
    sudo killall -9 lt-mull2sw > /dev/null 2>&1
    sudo killall -9 lt-mulfab > /dev/null 2>&1
    sudo killall -9 lt-multr > /dev/null 2>&1
    sudo killall -9 lt-mul > /dev/null 2>&1
    echo "Mul is stopped..."
}

function start-command {
case "$1" in
"l2switch")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/application/l2switch/ >> /dev/null
    sudo ./mull2sw -V 6000 -d
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000  -d
    popd >> /dev/null
    echo "Mul l2switch mode is running.."
    ;;
"fabric")
    pushd  $curr_dir/mul/ >> /dev/null
    sudo ./mul -d
    popd >> /dev/null
    pushd  $curr_dir/services/loadable/topo_routing/ >> /dev/null
    sudo ./multr -d -V 8000
    popd >> /dev/null
    pushd  $curr_dir/application/fabric/ >> /dev/null
    sudo ./mulfab -d -V 9000
    popd >> /dev/null
    pushd  $curr_dir/application/cli/ >> /dev/null
    sudo ./mulcli -V 10000 -d
    popd >> /dev/null

    echo "Mul fabric mode is running.."
    ;;
*) echo "unknown flow commmand $1"
    usage mul_startup.sh
esac
}


function usage {
    echo "Usage :"
    echo "$1 start l2switch"
    echo "$1 start fabric"
    echo "$1 stop"
}

if [ $# -lt 1 ]
then
    echo "Here"
    usage $0 
  exit
fi

echo "[MUL startup script]"

case "$1" in

"start")
    start-command $2
    ;;
"stop")
    stop-command
        ;;
*) echo "unknown command"
    usage $0
   ;;
esac
