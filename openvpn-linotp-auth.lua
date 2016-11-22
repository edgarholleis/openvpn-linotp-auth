#!/usr/bin/env lua

--  OpenVPN management interface client (attached to OpenVPN server)
--  Authenticates against LinOTP, uses OpenVPN challenge / response
--  protocol to ask separately for username / password and OTP pin.
--
--  Copyright (C) 2016 Edgar Holleis
--
--  This program is distributed under the terms of the  GPL version 3 or later,
--  see https://www.gnu.org/licenses/gpl-3.0.en.html
-- 
--
--  OpenVPN config (server):
--      management 127.0.0.1 1193
--      managment-client-auth
--      client-cert-not-required
--      reneg-sec 0
--
--  OpenVPN config (client):
--      auth-user-pass
--      reneg-sec 0
--      auth-nocache
--      static-challenge "Enter Token Pin" 1     (for static challenge/response)
--      auth-retry interact                     (for dynamic challenge/response)
--


-- Configuration
local connectaddr = "127.0.0.1"
local connectport = 1193
local bindaddr = nil
local bindport = nil

local challengetext = "Enter token pin"

local linotpurl = "https://127.0.0.1:443/validate/check"
local linotpsslparams = {
  mode = "client",
  protocol = "sslv23",
  cafile = "/etc/ssl/certs/linotpserver.pem", --self signed server cert of LinOTP
  verify = "peer",
  options = {"all", "no_sslv3", "no_sslv2"}
}

local mitimeout = 5
local linotptimeout = 2


-- Includes
local socket = require("socket")
local http = require("socket.http")
local ltn12 = require("ltn12")
local ssl = require("ssl")
local lpeg = require("lpeg")
local mime = require("mime")
local json = require("dkjson")


-- LPeg spec for OpenVPN MI
local p_white = lpeg.S(" \t") ^ 0
local p_async = lpeg.P(">")
local p_comma = p_white * lpeg.P(",") * p_white
local p_equal = p_white * lpeg.P("=") * p_white
local p_integer = lpeg.R("09") ^ 1 / tonumber
local p_escapechar = (lpeg.P("\\") * lpeg.C(1)) / "%1"
local p_escapeseq1 = lpeg.Cs(((lpeg.P(1) - lpeg.S("\\\"")) + p_escapechar) ^ 0)
local p_escapeseq2 = lpeg.Cs((p_white * ((lpeg.P(1) - lpeg.S("\\ \t")) + p_escapechar) ^ 1) ^ 0)
local p_val = 
        (lpeg.P("\"") * lpeg.Cg(p_escapeseq1, "val") * lpeg.P("\"")) + 
        (lpeg.P("\'") * lpeg.Cg(((lpeg.P(1) - lpeg.P("\'")) ^ 0), "val") * lpeg.P("\'")) + 
        lpeg.Cg(p_escapeseq2, "val")
local p_valorempty = p_val + lpeg.Cg(0, "val")
local p_variable = lpeg.Cg((lpeg.P(1) - lpeg.S("= \t")) ^ 0, "var") * p_equal * p_valorempty
local p_eol = lpeg.P(-1)

local p_clientconnect = p_async * lpeg.C("CLIENT:CONNECT") * 
        p_comma * lpeg.Ct(lpeg.Cg(p_integer, "_cid") * 
        p_comma * lpeg.Cg(p_integer, "_kid")) * p_white * p_eol
local p_clientenv = p_async * lpeg.C("CLIENT:ENV") * 
        p_comma * lpeg.Ct(p_variable) * p_white * p_eol
local p_clientend = p_async * lpeg.C("CLIENT:ENV") * 
        p_comma * lpeg.P("END") * p_white * p_eol

local p_clientreauth = p_async * lpeg.C("CLIENT:REAUTH") * 
        p_comma * lpeg.Ct(lpeg.Cg(p_integer, "_cid") * 
        p_comma * lpeg.Cg(p_integer, "_kid")) * p_white * p_eol

local p_info = p_async * lpeg.C("INFO") * lpeg.P(1) ^ 0 * p_eol

local p_clientdisconnect = p_async * lpeg.C("CLIENT:DISCONNECT") *
        p_comma * lpeg.Ct(lpeg.Cg(p_integer, "_cid")) * p_white * p_eol

local p_clientestablished = p_async * lpeg.C("CLIENT:ESTABLISHED") *
        p_comma * lpeg.Ct(lpeg.Cg(p_integer, "_cid")) * p_white * p_eol

local p_clientaddress = p_async * lpeg.C("CLIENT:ADDRESS") *
        p_comma * lpeg.Ct(lpeg.Cg(p_integer, "_cid") * 
        p_comma * lpeg.Cg(lpeg.R("09", "..", "::") ^ 0, "_ip") *
        p_comma * lpeg.Cg(p_integer, "_pri")) * p_white * p_eol


-- LPeg spec for OpenVPN c/r protocol
local p_base64 = lpeg.R("AZ", "az", "09", "++", "//", "==") ^ 0
local p_scrv1 = lpeg.C("SCRV1") * 
        lpeg.Ct(lpeg.P(":") * lpeg.Cg(p_base64, "pw") * lpeg.P(":") * 
        lpeg.Cg(p_base64, "pin")) * p_eol
local p_crv1 = lpeg.C("CRV1") * 
        lpeg.Ct(lpeg.P("::") * lpeg.Cg(p_base64, "state") * lpeg.P("::") * 
        lpeg.Cg(lpeg.P(1) ^ 0, "pin")) * p_eol


function url_encode(str)
  if (str) then
    str = string.gsub (str, "\n", "\r\n")
    str = string.gsub (str, "([^%w %-%_%.%~])",
        function (c) return string.format ("%%%02X", string.byte(c)) end)
    str = string.gsub (str, " ", "+")
  end
  return str
end


-- Check username, password and pin against LinOTP
function linotp_authenticate (username, password, pin)
    try = socket.try

    function create()
        -- wrap http.resquest in ssl socket, see
        -- http://lua-users.org/lists/lua-l/2009-02/msg00270.html

        local t = { c = try(socket.tcp()) }

        function idx (tbl, key)
            return function (prxy, ...)
                       local c = prxy.c
                       return c[key](c, ...)
                   end
        end

        function t:connect(host, port)
            try(self.c:settimeout(linotptimeout, "t"))
            try(self.c:connect(host, port))
            self.c = try(ssl.wrap(self.c, linotpsslparams))
            try(self.c:settimeout(linotptimeout, "t"))
            try(self.c:dohandshake())
            return 1
        end

        return setmetatable(t, {__index = idx})
    end

    -- build LinOTP URL
    local urlparam = "?user=" .. url_encode(username) ..
                     "&pass=" .. url_encode(password .. pin)
    
    local restable = {}
    local _, statuscode = http.request {
        url = linotpurl .. urlparam,
        sink = ltn12.sink.table(restable),
        redirect = false,
        create = create }
        
    if statuscode ~= 200 then
        print("linotp_authenticate https status: " .. statuscode)
        return nil, statuscode
    end
    
    local lintopresult = json.decode(table.concat(restable), 1, nil, nil)
    
    if lintopresult ~= nil and
            lintopresult.result ~= nil and
            lintopresult.result.status == true and
            lintopresult.result.value == true then
        return true, ""
    else 
        return false, ""
    end
end


function mi_command(mistate, cmd, params, cmdexpect)
    --print("mi_command: '" .. cmd .. " " .. params .. "'")
    local sock, try = mistate.sock, mistate.try
    try(sock:send(cmd .. " ".. params .. "\n"))
    if cmdexpect ~= nil then
        return cmdexpect
    else
        -- dummy expect that simply swallows the line
        return function (line) end
    end
end


-- MI message handlers
function do_clientconnect (mistate, cmd, params)
    
    -- check whether username, password is present
    if (params.username == nil or params.password == nil) then
        print("do_clientconnect: no username / password")
        return mi_command(mistate, "client-deny", 
            "" .. params._cid .. " " .. params._kid ..
            " \"no username/password\" \"no username/password\"")
    end
    
    -- try to decode password as CRV1 or SCRV1
    local password, pin
    local m, p = p_scrv1:match(params.password)
    if (m ~= nil) then
        password = mime.unb64(p.pw)
        pin = mime.unb64(p.pin)
        pin = pin:gsub("^([^\n]+).*$","%1") -- work around bug in OpenVPN
    end 
    
    m, p = p_crv1:match(params.password)
    if (m ~= nil) then
        password = mime.unb64(p.state)
        pin = p.pin
    end
    
    if (password == nil or pin == nil) then
        -- could not decode SCRV1 or CRV1 --> start CRV1
        return mi_command(mistate, "client-deny", 
            "" .. params._cid .. " " .. params._kid ..
            " \"CRV1\" \"CRV1:R,E:" .. mime.b64(params.password) .. ":" ..
            mime.b64(params.username) .. ":" .. challengetext .. "\"",
                function (line)
                    if not line:match("^SUCCESS:") then
                        print("OpenVPN rejects CRV1 challenge (user: " ..
                            params.username .. "): '" .. line .. "'")
                    end
                end)
    end
    
    -- Have username, password & pin: do authentication
    local authok, sc = linotp_authenticate(params.username, password, pin)
    if authok then
        return mi_command(mistate, "client-auth-nt", 
            "" .. params._cid .. " " .. params._kid,
            function (line)
                if not line:match("^SUCCESS:") then
                    print("OpenVPN rejects auth success (user: " .. 
                        params.username .. "): '" .. line .. "'")
                end
            end)
    else
        return mi_command(mistate, "client-deny", 
            "" .. params._cid .. " " .. params._kid ..
            " \"authentication failed, sc=" .. sc .. "\"" ..
            " \"authentication failed\"",
            function (line)
                if not line:match("^SUCCESS:") then
                    print("OpenVPN rejects auth fail (user: " .. 
                        params.username .. "): '" .. line .. "'")
                end
            end)
    end
end


-- MI message dispatch tables
local mi_messages = { 
    { p = p_clientconnect, has_env = true, f = do_clientconnect },
    { p = p_clientreauth, has_env = true, f = nil },
    { p = p_info, has_env = false, f = nil },
    { p = p_clientdisconnect, has_env = true, f = nil },
    { p = p_clientestablished, has_env = true, f = nil },
    { p = p_clientaddress, has_env = false, f = nil }
}


-- receive loop, parser
mgmt_client = socket:protect(function (sock)
    
    local try = socket.newtry(function() sock:close() end)
    local mistate = { sock = sock, try = try }
    
    local cur_mspec, cur_msg, cur_params = nil, nil, nil
    local cur_cmdexpect = { }
    
    while 1 do
        
        try(sock:settimeout(nil))
        local line = try(sock:receive())
        try(sock:settimeout(mitimeout))
        
        --print("line: " .. line)
        
        local is_msg = line:match("^>")
        
        if is_msg and cur_mspec == nil then
            -- try decoding as new MI msg
            for i, mspec in ipairs(mi_messages) do
                local m, p = mspec.p:match(line)
                if m ~= nil then
                    cur_mspec = mspec
                    cur_msg, cur_params = m, p
                    break
                end
            end
            
            if cur_mspec ~= nil and not cur_mspec.has_env then
                -- if msg has no env, do callback
                if cur_mspec.f ~= nil then
                    local cmdexpect = cur_mspec.f(mistate, cur_msg, cur_params)
                    if cmdexpect ~= nil then table.insert(cur_cmdexpect, cmdexpect) end
                end
                cur_mspec, cur_msg, cur_params = nil, nil, nil
            
            elseif cur_mspec == nil then
                print("!!Message: " .. line)
            end
            
        elseif is_msg then
            -- expecting an env to previous MI msg
            local m, p = p_clientenv:match(line)
            if m ~= nil then
                cur_params[p.var] = p.val
                        
            elseif p_clientend:match(line) ~= nil then
                if cur_mspec.f ~= nil then
                    local cmdexpect = cur_mspec.f(mistate, cur_msg, cur_params)
                    if cmdexpect ~= nil then table.insert(cur_cmdexpect, cmdexpect) end
                end
                cur_mspec, cur_msg, cur_params = nil, nil, nil
            
            else
                print("!Message: " .. line)
            end
            
        elseif cur_cmdexpect[1] ~= nil then
           -- expecting a command response
           cur_cmdexpect[1](line)
           table.remove(cur_cmdexpect, 1)
        
        else
            -- not expecting anything
            print("!Response: " .. line)
        end
        
    end
    
    try(sock:close())
end)


function sleep(sec)
    socket.select(nil, nil, sec)
end


-- main
if (bindaddr ~= nil and bindport ~= nil) then
    local server = assert(socket.bind(bindaddr, bindport))

    while 1 do
        -- wait for a connection from any client
        local client = server:accept()

        mgmt_client(client)
    end

elseif (connectaddr ~= nil and connectport ~= nil) then
    while 1 do
        local client = socket.tcp()
        client:settimeout(mitimeout)

        local result = client:connect(connectaddr, connectport)
        if (result) then
            mgmt_client(client)
        end
        
        sleep(2)
    end
end
        
        



