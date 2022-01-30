local utils = require "plugins.crowdsec.utils"


local M = {_TYPE='module', _NAME='ban.funcs', _VERSION='1.0-0'}

M.template_str = ""
M.redirect_location = ""
M.ret_code = ngx.HTTP_FORBIDDEN


function M.new(template_path, redirect_location, ret_code)
    if utils.file_exist(template_path) == false then
        return "ban template file doesn't exist, will ban without template"
    else
        M.template_str = utils.read_file(template_path)
        if M.template_str == nil then
            return "ban template file doesn't exist, will ban without template"
        else
    end
    M.REDIRECT_LOCATION = redirect_location
    M.ret_code = ret_code

    return nil
end


function M.apply()
    if M.redirect_location ~= "" then
        ngx.redirect(M.redirect_location)
        return
    end

    if template_str ~= "" then
        ngx.header.content_type = "text/html"
        ngx.say(template_str)
    end
    ngx.exit(ngx.ret_code)
    return
end

return M