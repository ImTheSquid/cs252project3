#!/bin/bash

echo -e "\033[1;4;93m\t While 1\033[0m"

input_str_sh=$'
   count=5
   while [ $count -ne 0 ]; do
     echo count: $count
     count=`expr $count - 1`
   done;
   '
input_str_shell=$'
   setenv count 5
   while [ $count -ne 0 ]; do
     echo count: $count
     setenv count `expr $count - 1`
   done;
   '
diff <(/bin/sh <<< "$input_str_sh" 2>&1) <(cargo run --quiet <<< "$input_str_shell" 2>&1)
exit $?
