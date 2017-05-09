{afterEach, beforeEach, describe, it} = global
{expect}     = require 'chai'
fs           = require 'fs'
jsonwebtoken = require 'jsonwebtoken'
path         = require 'path'
shmock       = require 'shmock'

formatPublicKey = require './helpers/format-public-key'
Verifier        = require '../src/verifier'

PRIVATE_KEY_1 = fs.readFileSync path.join(__dirname, './fixtures/1-private-key.pem'), 'utf8'
PUBLIC_KEY_1 = formatPublicKey fs.readFileSync(path.join(__dirname, './fixtures/1-public-key.pem'), 'utf8')
PUBLIC_KEY_2 = formatPublicKey fs.readFileSync(path.join(__dirname, './fixtures/2-public-key.pem'), 'utf8')

describe 'Verifier', ->
  beforeEach ->
    @microsoftonline = shmock()

    @sut = new Verifier
      publicKeysUrl: "http://localhost:#{@microsoftonline.address().port}"

  afterEach (done) ->
    @microsoftonline.close done

  describe '->publicKeyForKid', ->
    describe 'when called without a kid', ->
      beforeEach (done) ->
        @sut.publicKeyForKid null, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Expected kid to be a non-empty string.'

    describe 'when called with a non-string kid', ->
      beforeEach (done) ->
        @sut.publicKeyForKid 1, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Expected kid to be a non-empty string.'

    describe 'when called with an empty string kid', ->
      beforeEach (done) ->
        @sut.publicKeyForKid '', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Expected kid to be a non-empty string.'

    describe 'when called with a kid but the server returns a 404', ->
      beforeEach (done) ->
        @sut.publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Non 2xx response from microsoftonline: 404.'

    describe "when called with a kid that the server doesn't know about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "fdsa"
              x5c: ['public-key']
            }]
          }

        @sut.publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'The kid is not found on microsoftonline.'

    describe "when server returns a malformed response", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
            }]
          }

        @sut.publicKeyForKid 'asdf', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Response from microsoftonline was malformed.'

    describe "when called with a kid that the server knows about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
              x5c: ['public-key']
            }]
          }

        @sut.publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''

    describe "when the server returns a different public key", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "asdf"
              x5c: ['very-public-key']
            }]
          }

        @sut.publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          very-public-key
          -----END CERTIFICATE-----
        '''

    describe "when called with a different kid that the server knows about", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "lkj"
              x5c: ['public-key']
            }]
          }

        @sut.publicKeyForKid 'lkj', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''

    describe "when the server returns two keys", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, {
            keys: [{
              kid: "wrong"
              x5c: ['wrong-public-key']
            }, {
              kid: "asdf"
              x5c: ['public-key']
            }]
          }

        @sut.publicKeyForKid 'asdf', (error, @publicKey) => done(error)

      it 'should yield the different public key', ->
        expect(@publicKey).to.deep.equal '''
          -----BEGIN CERTIFICATE-----
          public-key
          -----END CERTIFICATE-----
        '''

  describe '->verify', ->
    describe 'when given a null JWT', ->
      beforeEach (done) ->
        @sut.verify null, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Expected JWT to be a non-empty string.'

    describe 'when given an empty-string JWT', ->
      beforeEach (done) ->
        @sut.verify '', (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Expected JWT to be a non-empty string.'

    describe 'when given a JWT in the wrong format', ->
      beforeEach (done) ->
        @sut.verify "malformed", (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Malformed JWT.'

    describe 'when given a valid JWT with an unknown kid', ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, { keys: [{ kid: "asdf", x5c: ['public-key'] }] }

        jwt = jsonwebtoken.sign {foo: 'bar'}, PRIVATE_KEY_1, {header: {kid: 'unknown'}, algorithm: 'RS256'}
        @sut.verify jwt, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'The kid is not found on microsoftonline.'

    describe "when given a valid JWT with an known kid, but the publicKey doesn't match the signature", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, { keys: [{ kid: "asdf", x5c: [PUBLIC_KEY_2] }] }

        jwt = jsonwebtoken.sign {foo: 'bar'}, PRIVATE_KEY_1, {header: {kid: 'asdf'}, algorithm: 'RS256', noTimestamp: true}
        @sut.verify jwt, (@error) => done()

      it 'should yield an error', ->
        expect(@error).to.exist
        expect(@error).to.be.an 'Error'
        expect(@error.message).to.deep.equal 'Invalid signature.'

    describe "when given a valid JWT with an known kid, and the publicKey matches the signature", ->
      beforeEach (done) ->
        @microsoftonline
          .get '/'
          .reply 200, { keys: [{ kid: "asdf", x5c: [PUBLIC_KEY_1] }] }

        jwt = jsonwebtoken.sign {foo: 'bar'}, PRIVATE_KEY_1, {header: {kid: 'asdf'}, algorithm: 'RS256', noTimestamp: true}
        @sut.verify jwt, (error, @decoded) => done(error)

      it 'should yield the decoded result', ->
        expect(@decoded).to.deep.equal {foo: 'bar'}
