# openvpn-linotp-auth
Authenticate OpenVPN against LinOTP 

## Features
* Supports OpenVPN challenge / response feature (separate entry of username / password / pin)
* Supports both static and dynamic challenge / response
* Uses OpenVPN management interface
* Uses LinOTP native https interface (validate/check)
* Written in LUA (runs on small devices, such as OpenWRT routers)
* Tested with TOTP based soft-tokens; probably supports other LinOTP tokens that work via validate/check

## Installation
* Set-up and test LinOTP (especially validate/check)
* Set-up and test OpenVPN with password authentication, e.g. against PAM
* Configure OpenVPN to authenticate against the management interface (see below)
* Edit openvpn-linotp-auth.lua, point it to OpenVPN and LinOTP
* Run openvpn-linotp-auth.lua, test it
* Daemonize openvpn-linotp-auth.lua

## OpenVPN config options
OpenVPN server:
* management 127.0.0.1 1193
* managment-client-auth
* client-cert-not-required
* reneg-sec 0

OpenVPN client:
* auth-user-pass
* reneg-sec 0
* auth-nocache
* static-challenge "Enter Token Pin" 1 (for static challenge/response)
* auth-retry interact (for dynamic challenge/response)


