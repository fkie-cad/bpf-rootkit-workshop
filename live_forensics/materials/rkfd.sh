#!/usr/bin/env bash

# Finds all those nasty rootkits, guaranteed.
# Usage: sudo ./rkfd.sh

for i in `seq 1 10000`;
do
  one=`cat /proc/$i/cmdline`
  one_exit=$?
  exec 3< "/proc/$i/cmdline"
  two=`cat <&3`
  if [[ $one != $two ]] && [[ $one_exit == 1 ]]
  then
    echo "Oh, oh: Looks like you have a rooootkit on your system: PID($i) cmdline($two)"
    echo "Calling Cyberpolice ...  HueHueHueHueHueHueHueHueHueHueHueHue"
  fi
  exec 3<&-
done 2>/dev/null
