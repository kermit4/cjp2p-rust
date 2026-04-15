#!/bin/bash
while [[ $1 ]];do
    sha=$(sha256sum "$1")
    sha=${sha% *}
    cp -v -p "$1" "cjp2p/public/$sha"
    echo "http://localhost:24255/$sha"
    shift
done

