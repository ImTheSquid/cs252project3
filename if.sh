#!/bin/bash

echo -e "\033[1;4;93m\t If 2\033[0m"

input_str=$'
   if [ -f test_if_1 ]; then
       echo Exists 1;
   fi;
   if [ ! -f test_if_1 ]; then
       echo Exists 2;
   fi;
   if [ 0 -ne 1 ]; then
       echo Not Equal 1;
   fi;
   if [ ! 0 -ne 1 ]; then
       echo Not Equal 2;
   fi;
   '
diff <(/bin/sh <<< "$input_str" 2>&1) <(cargo run --quiet <<< "$input_str" 2>&1)
exit $?
