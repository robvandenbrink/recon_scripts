local http = require "http"
local io = require "io"
local ipOps = require "ipOps"
local json = require "json"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local tab = require "tab"
local table = require "table"
local openssl = stdnse.silent_require "openssl"


-- Set your IPInfo API key here to avoid typing it in every time:
-- local apiKey = ""

author = "Rob VandenBrink <rob@coherentsecurity.com>"
based_on = "shodan-api.nse, written by Glenn Wilkinson <glenn@sensepost.com> (idea: Charl van der Walt <charl@sensepost.com>)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "external"}

description = [[
Queries IPInfo API for given targets and produces similar output to
a -sV nmap scan. The IPInfoAPI key can be set with the 'apikey' script
argument, or hardcoded in the .nse file itself. You can get a free key from
https://developer.IPInfo.io

N.B if you want this script to run completely passively make sure to
include the -sn -Pn -n flags.
]]

---
-- @usage
--  nmap --script IPInfo-api x.y.z.0/24 -sn -Pn -n --script-args 'IPInfo-api.outfile=potato.csv,IPInfo-api.apikey=IPInfoAPIKEY'
--  nmap --script IPInfo-api --script-args 'IPInfo-api.target=x.y.z.a,IPInfo-api.apikey=IPInfoAPIKEY'
--
-- @output
-- | IPInfo-api: Report for 2600:3c01::f03c:91ff:fe18:bb2f (scanme.nmap.org)
-- | PORT	PROTO	PRODUCT      VERSION
-- | 80   tcp   Apache httpd
-- | 3306 tcp   MySQL        5.5.40-0+wheezy1
-- | 22   tcp   OpenSSH      6.0p1 Debian 4+deb7u2
-- |_443  tcp
--
--@args IPInfo-api.outfile Write the results to the specified CSV file
--@args IPInfo-api.apikey Specify the IPInfoAPI key. This can also be hardcoded in the nse file.
--@args IPInfo-api.target Specify a single target to be scanned.
--
--@xmloutput
-- <table key="hostnames">
--   <elem>scanme.nmap.org</elem>
-- </table>
-- <table key="ports">
--   <table>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">22</elem>
--   </table>
--   <table>
--     <elem key="version">2.4.7</elem>
--     <elem key="product">Apache httpd</elem>
--     <elem key="protocol">tcp</elem>
--     <elem key="number">80</elem>
--   </table>
-- </table>

-- ToDo: * Have an option to complement non-banner scans with IPInfo data (e.g. -sS scan, but
--          grab service info from IPInfo
--       * Have script arg to include extra host info. e.g. Coutry/city of IP, datetime of
--          scan, verbose port output (e.g. smb share info)
--       * Warn user if they haven't set -sn -Pn and -n (and will therefore actually scan the host
--       * Accept IP ranges via the script argument 'target' parameter


-- Begin
if not nmap.registry[SCRIPT_NAME] then
  nmap.registry[SCRIPT_NAME] = {
    apiKey = stdnse.get_script_args(SCRIPT_NAME .. ".apikey") or apiKey,
    count = 0
  }
end
local registry = nmap.registry[SCRIPT_NAME]
local outFile = stdnse.get_script_args(SCRIPT_NAME .. ".outfile")
local arg_target = stdnse.get_script_args(SCRIPT_NAME .. ".target")

local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

local function lookup_target (target)
  local response = http.get("ipinfo.io", 443, "/".. target .."/json?token=" .. registry.apiKey, {any_af = true})

  local stat, retval = json.parse(response.body)
  if not stat then
    stdnse.debug1("Error parsing IPInfo response: %s", resp)
    return nil
  end
  return response.body
end


prerule = function ()
  if (outFile ~= nil) then
    local file = io.open(outFile, "w")
    io.output(file)
    io.write("resp.data\n")
  end

  if registry.apiKey == "" then
    registry.apiKey = nil
  end

  if not registry.apiKey then
    stdnse.verbose1("Error: Please specify your API key with the %s.apikey argument", SCRIPT_NAME)
    return false
  end

  if arg_target then
    local is_ip, err = ipOps.expand_ip(arg_target)
    if not is_ip then
      stdnse.verbose1("Error: %s.target must be an IP address", SCRIPT_NAME)
      return false
    end
    return true
  end
end

local function format_output(resp)
  if resp.error then
    return resp.error
  end
  if resp.data then
    tab_out = json.parse(resp.body)
    return out, tab_out
  else
    return resp.body
  end
end


generic_action = function(ip)
  local resp = lookup_target(ip)

  if not resp then return nil end
  local out, tabular = format_output(resp)
  if type(out) == "string" then
    -- some kind of error
    return out
  end
  local result = string.format(resp)
 
  return out, result
end

preaction = function()
  return generic_action(arg_target)
end

hostrule = function(host)
  return registry.apiKey and not ipOps.isPrivate(host.ip)
end

hostaction = function(host)
  return generic_action(host.ip)
end

postrule = function ()
  return registry.apiKey
end

postaction = function ()
  local out = { "IPInfo done: ", registry.count, " hosts up." }
  if outFile then
    io.close()
    out[#out+1] = "\nWrote IPInfo output to: "
    out[#out+1] = outFile
  end
  return table.concat(out)
end

local ActionsTable = {
  -- prerule: scan target from script-args
  prerule = preaction,
  -- hostrule: look up a host in IPInfo
  hostrule = hostaction,
  -- postrule: report results
  postrule = postaction
}

-- execute the action function corresponding to the current rule
action = function(...) return ActionsTable[SCRIPT_TYPE](...) end
