local singletons = require "kong.singletons"
local cjson      = require "cjson"
local utils      = require "kong.tools.utils"

-- can return nil
local function parse_name_list(input, errors)
  local name_list
  if type(input) == "string" then
    name_list = utils.split(input, ",")
  elseif type(input) == "table" then
    name_list = utils.shallow_copy(input)
  elseif input == ngx.null then
    name_list = {}
  end

  if not name_list then
    return nil
  end

  local found = {}
  for _, name in ipairs(name_list) do
    if found[name] then
      local msg   = "duplicate server name in request: " .. name
      local err_t = errors:invalid_input(msg)
      return nil, tostring(err_t), err_t
    end
    found[name] = true
  end

  table.sort(name_list)
  return setmetatable(name_list, cjson.empty_array_mt)
end


local _Certificates = {}


function _Certificates:insert_with_name_list(cert)
  local db = singletons.db
  local name_list, err, err_t = parse_name_list(cert.server_names, self.errors)
  if err then
    return nil, err, err_t
  end

  if name_list then
    local ok, err, err_t = db.server_names:check_list_is_new(name_list)
    if not ok then
      return nil, err, err_t
    end
  end

  cert.server_names = nil
  cert, err, err_t = assert(self:insert(cert))
  if not cert then
    return nil, err, err_t
  end
  cert.server_names = name_list or cjson.empty_array

  if name_list then
    local ok, err, err_t = db.server_names:insert_list({id = cert.id}, name_list)
    if not ok then
      return nil, err, err_t
    end
  end

  return cert
end


function _Certificates:update_with_name_list(cert_pk, cert)
  local db = singletons.db
  local name_list, err, err_t = parse_name_list(cert.server_names, self.errors)
  if err then
    return nil, err, err_t
  end

  if name_list then
    local ok, err, err_t =
      db.server_names:check_list_is_new_or_in_cert(cert_pk, name_list)
    if not ok then
      return nil, err, err_t
    end
  end

  -- update certificate if necessary
  if cert.key or cert.cert then
    cert.server_names = nil
    cert, err, err_t = self:update(cert_pk, cert)
    if err then
      return nil, err, err_t
    end
  end
  cert.server_names = name_list or cjson.empty_array

  if name_list then
    local ok, err, err_t = db.server_names:update_list(cert, name_list)
    if not ok then
      return nil, err, err_t
    end
  end

  return cert
end


function _Certificates:select_by_server_name(name)
  local db = singletons.db

  local sn, err, err_t = db.server_names:select_by_name(name)
  if err then
    return nil, err, err_t
  end
  if not sn then
    local err_t = self.errors:not_found({ name = name })
    return nil, tostring(err_t), err_t
  end

  return self:select(sn.certificate)
end


function _Certificates:select_with_name_list(cert_pk)
  local db = singletons.db

  local cert, err, err_t = db.certificates:select(cert_pk)
  if err_t then
    return nil, err, err_t
  end

  if not cert then
    local err_t = self.errors:not_found(cert_pk)
    return nil, tostring(err_t), err_t
  end

  cert.server_names, err, err_t = db.server_names:list_for_certificate(cert_pk)
  if err_t then
    return nil, err, err_t
  end

  return cert
end


function _Certificates:delete(cert_pk)
  local db = singletons.db

  local name_list, err, err_t =
    db.server_names:list_for_certificate(cert_pk)
  if not name_list then
    return nil, err, err_t
  end

  local ok, err, err_t = db.server_names:delete_list(name_list)
  if not ok then
    return nil, err, err_t
  end

  return self.super.delete(self, cert_pk)
end


return _Certificates
