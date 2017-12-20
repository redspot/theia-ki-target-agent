if [ "x${WRAP}" == "x" ]; then
	exit 1
fi

nargs=$#
args=
while [ $nargs -gt 0 ]
do
  args="\"\${$nargs}\" $args"
  nargs=`expr $nargs - 1`
done
eval exec ${WRAP} $args
