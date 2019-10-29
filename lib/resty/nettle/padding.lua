return {
  ansix923      = require "resty.nettle.padding.ansix923",
  base64        = require "resty.nettle.padding.base64",
  iso7816_4     = require "resty.nettle.padding.iso7816-4",
  ["iso7816-4"] = require "resty.nettle.padding.iso7816-4",
  iso10126      = require "resty.nettle.padding.iso10126",
  nopadding     = require "resty.nettle.padding.nopadding",
  pkcs7         = require "resty.nettle.padding.pkcs7",
  spacepadding  = require "resty.nettle.padding.spacepadding",
  zeropadding   = require "resty.nettle.padding.zeropadding",
}
