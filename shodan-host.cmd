@echo off
curl -s -k GET "https://api.shodan.io/shodan/host/%1?key=%APIKEY_SHODAN%" | jq
