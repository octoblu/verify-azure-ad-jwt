jsonwebtoken = require 'jsonwebtoken'
capitalize   = require 'lodash/fp/capitalize'
find         = require 'lodash/fp/find'
get          = require 'lodash/fp/get'
isEmpty      = require 'lodash/fp/isEmpty'
isString     = require 'lodash/fp/isString'
request      = require 'request'
PUBLIC_KEYS_URL = 'https://login.microsoftonline.com/common/discovery/keys'

class Verifier
  constructor: ({ @publicKeysUrl }={}) ->
    @publicKeysUrl ?= PUBLIC_KEYS_URL

  publicKeyForKid: (kid, callback) =>
    return callback new Error 'Expected kid to be a non-empty string.' unless isString(kid) && !isEmpty(kid)

    request.get @publicKeysUrl, json: true, (error, response, body) =>
      return callback error if error?
      return callback new Error "Non 2xx response from microsoftonline: #{response.statusCode}." if response.statusCode > 299

      key = find {kid}, body.keys
      return callback new Error 'The kid is not found on microsoftonline.' unless key?

      publicKey = get 'x5c.0', key
      return callback new Error 'Response from microsoftonline was malformed.' unless publicKey?
      return callback null, """
        -----BEGIN CERTIFICATE-----
        #{publicKey}
        -----END CERTIFICATE-----
      """

  verify: (jwt, callback) =>
    return callback new Error 'Expected JWT to be a non-empty string.' unless isString(jwt) && !isEmpty(jwt)

    kid = get 'header.kid', jsonwebtoken.decode(jwt, complete: true)
    return callback new Error 'Malformed JWT.' unless kid?
    @publicKeyForKid kid, (error, publicKey) =>
      return callback error if error?
      jsonwebtoken.verify jwt, publicKey, algorithms: ['RS256'], (error, decoded) =>
        return callback @_formatJWTError error.message if error?
        callback error, decoded

  _formatJWTError: (message) =>
    new Error "#{capitalize message}."

module.exports = Verifier
