Verifier = require './src/verifier'

verify = (jwt, callback) =>
  verifier = new Verifier
  verifier.verify jwt, callback

module.exports = verify
module.exports.Verifier = Verifier
