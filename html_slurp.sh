#!/bin/bash
if ! [[ $1 ]];then
    echo usage $0 URL
    exit -1
fi
rm -rf html_slurp
mkdir -p html_slurp
cd html_slurp
wget -nv -p -H -k  "$@"

ln "$a" $b
done
d=
recurse() { 
    (builtin cd "$1"
    export d="../$d"
    find "$d" -mindepth 2 -type f|while read s;do 
        sha=$(find "$d" -maxdepth 1 -samefile "$s")
        find -type f -maxdepth 1 -exec sed   -i "s<$s<$sha<g" {} +  
    done
    for dd in */;do  
        [[ -d $dd ]] && recurse "$dd"
    done)
}
for a in */;do 
    recurse  "$a"
done
find */ -type f -exec sha256sum {} +|while read b a;do 
ln -f "$a" $b
done
find -maxdepth 1 -samefile "${1#http*://}" -printf "http://127.0.0.1:24254/%f\n"
