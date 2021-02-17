#!/bin/bash

checksum () {
   curl -s https://api.github.com/repos/ca-gip/dploy/releases/latest \
  | grep browser_download_url \
  | grep checksums \
  | cut -d '"' -f 4 \
  | xargs curl -sL
}

if [ "$(uname)" == "Darwin" ]; then
  echo "Downloading Darwin Release"
  mkdir -p /var/tmp/dploy
  curl -s https://api.github.com/repos/ca-gip/kubi-cli/releases/latest \
    | grep browser_download_url \
    | grep darwin_amd64 \
    | cut -d '"' -f 4 \
    | xargs curl -sL \
    | tar xf - -C /var/tmp/kubi-cli/
    sudo sh -c 'mv /var/tmp/dploy/kubi /usr/local/bin/ && chmod +x /usr/local/bin/kubi'
    rm -rf /var/tmp/dploy
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
  echo "Downloading Linux Release"
  mkdir -p /tmp/kubi-cli
  curl -s  https://api.github.com/repos/ca-gip/kubi-cli/releases/latest \
    | grep browser_download_url \
    | grep linux_amd64 \
    | cut -d '"' -f 4 \
    | xargs curl -sL \
    | tar xzf - -C /tmp/kubi-cli
    sudo sh -c 'mv /tmp/kubi-cli/kubi-cli /usr/local/bin/ && chmod +x /usr/local/bin/kubi'
    rm -rf /tmp/kubi-cli
elif [ "$(expr substr $(uname -s) 1 5)" == "Windows" ]; then
  echo "Downloading Windows Release"
  mkdir -p /tmp/kubi-cli
  curl -s  https://api.github.com/repos/ca-gip/kubi-cli/releases/latest \
    | grep browser_download_url \
    | grep windows_amd64 \
    | cut -d '"' -f 4 \
    | xargs curl -sL \
    | tar xzf - -C /tmp/kubi-cli
    sudo sh -c 'mv /tmp/kubi-cli/kubi-cli /usr/local/bin/ && chmod +x /usr/local/bin/kubi'
    rm -rf /tmp/kubi-cli
else echo "Unsupported OS" && exit 1
fi

echo "Install done !"