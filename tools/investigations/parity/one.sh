#!/bin/sh
# 打印单个 ELF 的动态未定义符号（去版本后缀），每行 "sym<TAB>file"
f="$1"
readelf -sW --dyn-syms "$f" 2>/dev/null | awk '$7=="UND" && ($4=="FUNC"||$4=="IFUNC"||$4=="OBJECT"){print $8}' \
  | sed 's/@.*//' | sort -u | awk -v F="$f" '{print $0"\t"F}'
