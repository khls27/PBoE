--
-- Created by IntelliJ IDEA.
-- User: khls27
-- Date: 18/1/17
-- Time: 下午2:35
-- PPP Bridge over Ethernet, soft AC-AP management
--

local require, os, tonumber, string, ipairs, table, type = require, os, tonumber, string, ipairs, table, type
local sysinfo = require "ripple.sysinfo"
local network = require "util.network"
local log = require("ripple.log").log

local PBOE_IFNAME = "pb0"
local _M = {}

local function is_valid_mac(macstr)
    local mack = {}
    local zn = 0
    local bn = 0

    if type(macstr) ~= "string" then
        return false
    end

    mack[1], mack[2], mack[3], mack[4], mack[5], mack[6] = macstr:match("^(%x+):(%x+):(%x+):(%x+):(%x+):(%x+)$")
    for i = 1, 6 do
        local maci = tonumber(mack[i], "16")
        if nil == maci then
            return false
        end

        mack[i] = maci
        if maci == 255 then
            bn = bn + 1
        elseif
        maci == 0 then
            zn = zn + 1
        end
    end
    -- boadcast or ALL-Zero
    if bn == 6 or zn == 6 then
        return false
    end

    -- group cast
    if mack[1] % 2 ~= 0 then
        return false
    end

    return true
end

local function is_mac_eq(mac1, mac2)
    if (not is_valid_mac(mac1)) or (not is_valid_mac(mac2)) then
        return false
    end

    return (mac1 == mac2)
end

function string:split(sep)
    local sep, fields = sep or " ", {}
    local pattern = string.format("([^%s]+)", sep)
    self:gsub(pattern, function(c) fields[#fields + 1] = c end)
    return fields
end

local function ac_conf_network()
    local cursor = require("uci").cursor()
    if not network.is_noportal() then
        return
    end

    local ifname = cursor:get("network", "hotspot", "ifname") or ""
    if ifname:find(PBOE_IFNAME) == nil then
        ifname = ifname .. " " .. PBOE_IFNAME
        cursor:set("network", "hotspot", "ifname", ifname)
        cursor:commit("network")
    end
end

local function ap_conf_network()
    local cursor = require("uci").cursor()
    local ifname = cursor:get("network", "hotspot", "ifname") or ""
    local nifname = PBOE_IFNAME
    if ifname:find(PBOE_IFNAME) == nil then

        local ifs = ifname:split()

        for _, ifn in ipairs(ifs) do
            if ifn:match("\.3") == nil then
                nifname = nifname .. " " .. ifn
            end
        end
        cursor:set("network", "hotspot", "ifname", nifname)
        cursor:commit("network")
        log("pboemng", "info", "change AP's network config")
    end
end

_M.get_ifmac = function()
    local network = require "util.network"
    local ifmac
    local wk_mode = sysinfo.work_mode()

    if wk_mode == "AC" and (not network.is_noportal()) then
        return nil
    end

    ifmac = (wk_mode == "AC" and sysinfo.ac_mode() == "ac_bypass")
            and (network.wanmac() or "")
            or network.local_mac()

    if ifmac and is_valid_mac(ifmac) then
        return ifmac
    end
    return nil
end

_M.pboe_start_ac = function()
    if sysinfo.work_mode() ~= "AC" then
        return
    end

    if not network.is_noportal() then
        log("pboemng", "info", "mutil-network not been set, do NOT start PBOE")
        return
    end

    local lif = "br-lan"
    if sysinfo.ac_mode() == "ac_bypass" then
        local cursor = require("uci").cursor()
        lif = cursor:get("network", "wan", "ifname")
    end

    if os.execute("upboe -s -i " .. lif .. " -b br-hotspot") ~= 0 then
        log("pboemng", "info", "fail to start PBOE")
        return
    end
    ac_conf_network()
    log("pboemng", "info", "start PBOE as server mode done!")
end

_M.pboe_start_ap = function()
    local cmd = {};
    local cursor = require("uci").cursor()

    local ports = cursor:get("network", "hotspot", "ifname") or ""
    ports = ports:split()

    for _, port in ipairs(ports) do
        if port:match("\.3") then
            table.insert(cmd, "brctl delif br-hotspot " .. port)
        end
    end

    table.insert(cmd, "upboe -c -i br-lan -b br-hotspot")
    if os.execute(table.concat(cmd, ";")) ~= 0 then
        log("pboemng", "info", "fail to start PBOE")
    end
    ap_conf_network()
    log("pboemng", "info", "start PBOE as client mode done!")
end

_M.pboe_restart = function()
    os.execute("brctl delif  br-hotspot " .. PBOE_IFNAME .. " &>/dev/null")
    if sysinfo.work_mode() == "AC" then
        _M.pboe_start_ac()
    else
        _M.pboe_start_ap()
    end
end

_M.pboe_add_peer = function(mac)
    if (not is_valid_mac(mac)) then
        log("pboemng", "info", "the peer mac is not valid")
        return false
    end

    if is_mac_eq(mac, _M.get_ifmac()) then
        log("pboemng", "info", "the peer mac is ourself")
        return false
    end
    log("pboemng", "info", "try add the peer<%s>, AC is <%s>", mac, _M.get_ifmac())
    return (os.execute("upboe -a " .. mac) == 0)
end

return _M
