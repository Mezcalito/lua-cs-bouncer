local http = require "resty.http"
local cjson = require "cjson"
local template = require "plugins.crowdsec.template"
local utils = require "plugins.crowdsec.utils"

local M = {_TYPE='module', _NAME='recaptcha.funcs', _VERSION='1.0-0'}

local captcha_backend_url = {}
captcha_backend_url["recaptcha"] = "https://www.recaptcha.net/recaptcha/api/siteverify"
captcha_backend_url["hcaptcha"] = "https://hcaptcha.com/siteverify"
captcha_backend_url["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
captcha_backend_url["mcaptcha"] = ""

local captcha_frontend_js = {}
captcha_frontend_js["recaptcha"] = "https://www.recaptcha.net/recaptcha/api.js"
captcha_frontend_js["hcaptcha"] = "https://js.hcaptcha.com/1/api.js"
captcha_frontend_js["turnstile"] = "https://challenges.cloudflare.com/turnstile/v0/api.js"
captcha_frontend_js["mcaptcha"] = "https://cdn.jsdelivr.net/npm/@mcaptcha/vanilla-glue@0.1.0-rc2/dist/index.min.js"

local captcha_frontend_key = {}
captcha_frontend_key["recaptcha"] = "g-recaptcha"
captcha_frontend_key["hcaptcha"] = "h-captcha"
captcha_frontend_key["turnstile"] = "cf-turnstile"
captcha_frontend_key["mcaptcha"] = "mcaptcha"

M.SecretKey = ""
M.SiteKey = ""
M.BackendUrl = ""
M.Template = ""

function M.New(siteKey, secretKey, TemplateFilePath, captcha_provider, mcaptcha_host)

    if siteKey == nil or siteKey == "" then
      return "no recaptcha site key provided, can't use recaptcha"
    end
    M.SiteKey = siteKey

    if secretKey == nil or secretKey == "" then
      return "no recaptcha secret key provided, can't use recaptcha"
    end

    M.SecretKey = secretKey

    if TemplateFilePath == nil then
      return "CAPTCHA_TEMPLATE_PATH variable is empty, will ban without template"
    end
    if utils.file_exist(TemplateFilePath) == false then
      return "captcha template file doesn't exist, can't use recaptcha"
    end

    local captcha_template = utils.read_file(TemplateFilePath)
    if captcha_template == nil then
        return "Template file " .. TemplateFilePath .. "not found."
    end

    M.CaptchaProvider = captcha_provider

    site_key = M.SiteKey
    backend_url = captcha_backend_url[M.CaptchaProvider]
    if mcaptcha_host ~= nil or mcaptcha_host ~= "" then
      site_key = mcaptcha_host .. "/widget?sitekey=" .. M.SiteKey
      backend_url = mcaptcha_host .. "/api/v1/pow/siteverify"
    end

    M.BackendUrl = backend_url

    local template_data = {}
    template_data["captcha_site_key"] = site_key
    template_data["captcha_frontend_js"] = captcha_frontend_js[M.CaptchaProvider]
    template_data["captcha_frontend_key"] = captcha_frontend_key[M.CaptchaProvider]
    local view = template.compile(captcha_template, template_data)
    M.Template = view

    return nil
end


function M.GetTemplate()
    return M.Template
end

function M.GetCaptchaBackendKey()
    if M.CaptchaProvider == "mcaptcha" then
        return captcha_frontend_key[M.CaptchaProvider] .. "__token"
    end

    return captcha_frontend_key[M.CaptchaProvider] .. "-response"
end

function table_to_encoded_url(args)
    local params = {}
    for k, v in pairs(args) do table.insert(params, k .. '=' .. v) end
    return table.concat(params, "&")
end

function M.Validate(captcha_res, remote_ip)
    if M.CaptchaProvider == "mcaptcha" then
      return verify_token_for_mcaptcha()
    end 

    return verify_token()
end

function verify_token(captcha_res, remote_ip)
    local body = {
      secret   = M.SecretKey,
      response = captcha_res,
      remoteip = remote_ip
    }

    local data = table_to_encoded_url(body)
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(M.BackendUrl, {
      method = "POST",
      body = data,
      headers = {
        ["Content-Type"] = "application/x-www-form-urlencoded",
      },
    })
    httpc:close()

    if err ~= nil then
      return true, err
    end

    local result = cjson.decode(res.body)

    if result.success == false then
      for k, v in pairs(result["error-codes"]) do
        if v == "invalid-input-secret" then
          return true, "reCaptcha secret key is invalid"
        end
      end 
    end

    return result.success, nil
end

function verify_token_for_mcaptcha(captcha_res, remote_ip)
    local body = {
      token  = captcha_res,
      key    = M.SiteKey,
      secret = M.SecretKey
    }

    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(M.BackendUrl, {
      method = "POST",
      body = cjson.encode(body),
      headers = {
        ["Content-Type"] = "application/json",
      },
    })
    httpc:close()

    if err ~= nil then
      return true, err
    end

    return res.valid, nil
end

return M
