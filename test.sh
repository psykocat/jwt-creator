#!/usr/bin/env bash
set -eu

# set of commands to validate that everything is working
_script="./jwt_creator.py"
_jfile="example.json"
_tfile="encoded_example.txt"

${_script} -l
${_script} -e ${_jfile}
${_script} -e ${_jfile} -s "foobar"
${_script} -d ${_tfile}

cat ${_jfile}|${_script} -e
cat ${_tfile}|${_script} -d

#END
