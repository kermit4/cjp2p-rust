#!/bin/bash
if ! [[ $1 ]];then
    echo usage $0 URL
    exit -1
fi
rm -rf html_slurp
mkdir -p html_slurp
cd html_slurp
wget -nv -p -H -k  "$@"
d=
change() {
    s=$1;f=$2
    grep -F $f circular_check  && return
    if grep -IqF "$s" "$f" ;then
        echo $f >> circular_check
        sha_s=$(sha256sum "$s"|cut -d ' ' -f 1)
        sha_f=$(sha256sum "$f"|cut -d ' ' -f 1)
        sed   -i "s<$s<$sha_s<g" "$f"
        find $d/*/ -type f |while read ff;do
            change "$sha_f" "$ff"
        done
    fi
}
recurse() { 
    echo "cd $1"
    (builtin cd "$1"
    export d="../$d"
    find -maxdepth 1 -type f |while read f;do
        file "$f" | grep -iq html || continue
        find "$d" -mindepth 2 -type f|while read s;do 
            >circular_check
            change "$s" "$f"
            rm -f circular_check
        done
    done
    for dd in */;do  
        [[ -d $dd ]] && recurse "$dd"
    done)
}
for a in */;do 
    recurse  "$a"
done
find */ -type f -exec sha256sum {} +|while read b a;do 
    ln -f "$a" ../cjp2p/public/$b
done
find ../cjp2p/public/ -samefile "${1#http*://}" -printf "http://127.0.0.1:24254/%f\n"
