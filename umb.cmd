@echo off
curl -s -k "https://investigate.api.umbrella.com//pdns/ip/%1" -H "Authorization: Bearer %umb-api-key%" -H "Content-Type: application/json"  | jq   | grep rr  | sed -e s/\"rr\"://g | tr -d \,\"" "
