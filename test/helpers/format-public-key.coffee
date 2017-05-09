join  = require 'lodash/fp/join'
split = require 'lodash/fp/split'

formatPublicKey = (publicKeyPem) =>
  lines = split '\n', publicKeyPem
  return join '', lines[1...-2]

module.exports = formatPublicKey
