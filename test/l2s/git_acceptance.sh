#!/bin/sh
# 真实 git 验收（guest 内执行）：init/add/commit/log/status/fsck/clone/
# checkout/gc，外加硬链接矩阵。由 test/RUN_L2S_GIT.sh 经 bxroot-run 调用。
#   $1 = 工作目录（guest 视角）
set -u
R=${1:-/tmp/g2probe}; rm -rf $R $R-clone; mkdir -p $R && cd $R || exit 9
fail=0; chk(){ if [ "$1" != 0 ]; then echo "FAIL $2 (rc=$1)"; fail=1; else echo "ok   $2"; fi; }
git init -q . ; git config user.email t@t; git config user.name t
mkdir -p d/e; echo hi > f; echo deep > d/e/g
git add -A; chk $? add
git commit -qm first; chk $? commit
echo more >> f; git commit -qam second; chk $? commit2
[ "$(git log --oneline | wc -l)" = 2 ]; chk $? "log=2"
[ -z "$(git status --porcelain)" ]; chk $? "status clean"
out=$(git fsck 2>&1); [ -z "$out" ]; chk $? "fsck clean: $(echo "$out" | head -2 | tr '\n' ' ')"
n=$(find .git -name '.l2s.*' | wc -l); [ "$n" = 0 ]; chk $? "no .l2s residue in .git ($n)"
git clone -q $R $R-clone 2>/tmp/gclone.err; rc=$?; [ -f $R-clone/d/e/g ] && [ $rc = 0 ]; chk $? "clone local $(head -1 /tmp/gclone.err)"
git checkout -q HEAD~1; chk $? checkout; [ "$(cat f)" = hi ]; chk $? "checkout content"
git checkout -q -; git gc -q 2>/tmp/ggc.err; chk $? "gc $(head -1 /tmp/ggc.err)"
out=$(git fsck 2>&1); [ -z "$out" ]; chk $? "fsck after gc"
# hard-link matrix
mkdir -p h/d1 h/d2; cd h; echo A > f; echo B > d1/a
ln f g && ln d1/a d1/b && ln d1/a d2/c; chk $? "ln matrix"
for x in f g d1/a d1/b d2/c; do cat $x >/dev/null 2>&1 || { echo "FAIL read $x"; fail=1; }; done
[ "$(stat -c %h d1/a)" = 3 ]; chk $? "nlink d1/a=3 (got $(stat -c %h d1/a))"
( cd d1 && cat ../f >/dev/null ); chk $? "read via ../"
# 证明 l2s 真的生效（否则整张表无证明力）：客户看到 nlink=2，但内核里是符号链接
real=$(python3 -c "import os;print(os.path.islink('f'), os.lstat('f').st_ino==os.lstat('g').st_ino)" 2>/dev/null)
echo "info l2s-evidence(python lstat islink,sameino)=$real"
exit $fail
