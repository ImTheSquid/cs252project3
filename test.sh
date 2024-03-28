date
#ls -l -a
echo root print
ls -la /
echo "test" >> testout.txt
echo "we append everything rn" >>& testout.txt
cat < testout.txt
echo different >&1
echo "test result" $?
ls -la | grep rwx
sleep 5 | echo "wake from thread" &
echo wake!
sleep 8
echo long wake
setenv aaa bbb
