/* global describe, it */

var assert = require('assert')
var BufferWriter = require('../src/bufferWriter')
var bcrypto = require('../src/crypto')
var bscript = require('../src/script')
var btemplates = require('../src/templates')
var coins = require('../src/coins')
var networks = require('../src/networks')
var varuint = require('varuint-bitcoin')
var ECPair = require('../src/ecpair')
var ECSignature = require('../src/ecsignature')
var Transaction = require('../src/transaction')
var TransactionBuilder = require('../src/transaction_builder')

var SIGHASH_ALL = Transaction.SIGHASH_ALL
var SIGHASH_NONE = Transaction.SIGHASH_NONE
var SIGHASH_SINGLE = Transaction.SIGHASH_SINGLE
var SIGHASH_ANYONECANPAY = Transaction.SIGHASH_ANYONECANPAY
var VALUE = 872000000
var ZERO = Buffer.alloc(32, 0)

function varSliceSize (someScript) {
  var length = someScript.length
  return varuint.encodingLength(length) + length
}

// independent reference implementations of the three digests, mirroring
// BIP143/ZIP243 — used to check the cached getters against first principles
function referencePrevoutHash (tx) {
  var bufferWriter = new BufferWriter(36 * tx.ins.length)
  tx.ins.forEach(function (txIn) {
    bufferWriter.writeSlice(txIn.hash)
    bufferWriter.writeUInt32(txIn.index)
  })
  if (coins.isZcash(tx.network)) {
    return tx.getBlake2bHash(bufferWriter.getBuffer(), 'ZcashPrevoutHash')
  }
  return tx.network.hashFunctions.transaction(bufferWriter.getBuffer())
}

function referenceSequenceHash (tx) {
  var bufferWriter = new BufferWriter(4 * tx.ins.length)
  tx.ins.forEach(function (txIn) {
    bufferWriter.writeUInt32(txIn.sequence)
  })
  if (coins.isZcash(tx.network)) {
    return tx.getBlake2bHash(bufferWriter.getBuffer(), 'ZcashSequencHash')
  }
  return tx.network.hashFunctions.transaction(bufferWriter.getBuffer())
}

function referenceOutputsHash (tx) {
  var txOutsSize = tx.outs.reduce(function (sum, output) {
    return sum + 8 + varSliceSize(output.script)
  }, 0)
  var bufferWriter = new BufferWriter(txOutsSize)
  tx.outs.forEach(function (out) {
    bufferWriter.writeUInt64(out.value)
    bufferWriter.writeVarSlice(out.script)
  })
  if (coins.isZcash(tx.network)) {
    return tx.getBlake2bHash(bufferWriter.getBuffer(), 'ZcashOutputsHash')
  }
  return tx.network.hashFunctions.transaction(bufferWriter.getBuffer())
}

function deterministicKeyPair (fillByte, network) {
  return ECPair.makeRandom({
    network: network,
    rng: function () { return Buffer.alloc(32, fillByte) }
  })
}

function buildTestTransaction (network, numIns, numOuts) {
  var tx = new Transaction(network)
  if (coins.isZcash(network)) {
    tx.version = 4
    tx.overwintered = 1
    tx.versionGroupId = 0x892f2085
  }
  var i
  for (i = 0; i < numIns; i++) {
    tx.addInput(bcrypto.sha256(Buffer.from('input-' + i)), i)
  }
  var outputScript = btemplates.pubKeyHash.output.encode(bcrypto.hash160(Buffer.from('pubkey-placeholder')))
  for (i = 0; i < numOuts; i++) {
    tx.addOutput(outputScript, VALUE + i)
  }
  return tx
}

describe('Transaction sighash digest caching', function () {
  var testNetworks = { flux: networks.flux, bitcoin: networks.bitcoin }

  Object.keys(testNetworks).forEach(function (name) {
    var network = testNetworks[name]

    describe(name, function () {
      it('cached digests equal independent reference implementations', function () {
        var tx = buildTestTransaction(network, 5, 2)

        // call repeatedly — first call populates the cache, rest must serve from it
        for (var i = 0; i < 3; i++) {
          assert.deepStrictEqual(tx.getPrevoutHash(SIGHASH_ALL), referencePrevoutHash(tx))
          assert.deepStrictEqual(tx.getSequenceHash(SIGHASH_ALL), referenceSequenceHash(tx))
          assert.deepStrictEqual(tx.getOutputsHash(SIGHASH_ALL, 0), referenceOutputsHash(tx))
        }
      })

      it('warm cache equals cold instance computation', function () {
        var warm = buildTestTransaction(network, 4, 2)
        // warm up the cache
        warm.getPrevoutHash(SIGHASH_ALL)
        warm.getSequenceHash(SIGHASH_ALL)
        warm.getOutputsHash(SIGHASH_ALL, 0)

        var cold = buildTestTransaction(network, 4, 2)
        assert.deepStrictEqual(warm.getPrevoutHash(SIGHASH_ALL), cold.getPrevoutHash(SIGHASH_ALL))
        assert.deepStrictEqual(warm.getSequenceHash(SIGHASH_ALL), cold.getSequenceHash(SIGHASH_ALL))
        assert.deepStrictEqual(warm.getOutputsHash(SIGHASH_ALL, 0), cold.getOutputsHash(SIGHASH_ALL, 0))
      })

      it('mutating a returned digest does not poison the cache', function () {
        var tx = buildTestTransaction(network, 3, 2)
        var first = tx.getPrevoutHash(SIGHASH_ALL)
        var expected = Buffer.from(first)
        first.fill(0)
        assert.deepStrictEqual(tx.getPrevoutHash(SIGHASH_ALL), expected)
      })

      it('addInput invalidates the cache', function () {
        var tx = buildTestTransaction(network, 3, 2)
        var before = tx.getPrevoutHash(SIGHASH_ALL)
        var beforeSequence = tx.getSequenceHash(SIGHASH_ALL)

        tx.addInput(bcrypto.sha256(Buffer.from('input-extra')), 99)

        assert.notDeepStrictEqual(tx.getPrevoutHash(SIGHASH_ALL), before)
        assert.notDeepStrictEqual(tx.getSequenceHash(SIGHASH_ALL), beforeSequence)
        assert.deepStrictEqual(tx.getPrevoutHash(SIGHASH_ALL), referencePrevoutHash(tx))
        assert.deepStrictEqual(tx.getSequenceHash(SIGHASH_ALL), referenceSequenceHash(tx))
      })

      it('addOutput invalidates the cache', function () {
        var tx = buildTestTransaction(network, 3, 2)
        var before = tx.getOutputsHash(SIGHASH_ALL, 0)

        var outputScript = btemplates.pubKeyHash.output.encode(bcrypto.hash160(Buffer.from('another-pubkey')))
        tx.addOutput(outputScript, VALUE * 2)

        assert.notDeepStrictEqual(tx.getOutputsHash(SIGHASH_ALL, 0), before)
        assert.deepStrictEqual(tx.getOutputsHash(SIGHASH_ALL, 0), referenceOutputsHash(tx))
      })

      it('SIGHASH_SINGLE outputs digest depends on inIndex and is never cached', function () {
        var tx = buildTestTransaction(network, 3, 2)
        // warm the SIGHASH_ALL cache first to ensure no cross-contamination
        tx.getOutputsHash(SIGHASH_ALL, 0)

        var single0 = tx.getOutputsHash(SIGHASH_SINGLE, 0)
        var single1 = tx.getOutputsHash(SIGHASH_SINGLE, 1)
        assert.notDeepStrictEqual(single0, single1)

        var cold = buildTestTransaction(network, 3, 2)
        assert.deepStrictEqual(single0, cold.getOutputsHash(SIGHASH_SINGLE, 0))
        assert.deepStrictEqual(single1, cold.getOutputsHash(SIGHASH_SINGLE, 1))
        // out of range single returns ZERO
        assert.deepStrictEqual(tx.getOutputsHash(SIGHASH_SINGLE, 5), ZERO)
      })

      it('hashType variants keep their not-applicable ZERO results', function () {
        var tx = buildTestTransaction(network, 3, 2)
        tx.getPrevoutHash(SIGHASH_ALL) // warm cache

        assert.deepStrictEqual(tx.getPrevoutHash(SIGHASH_ALL | SIGHASH_ANYONECANPAY), ZERO)
        assert.deepStrictEqual(tx.getSequenceHash(SIGHASH_ALL | SIGHASH_ANYONECANPAY), ZERO)
        assert.deepStrictEqual(tx.getSequenceHash(SIGHASH_SINGLE), ZERO)
        assert.deepStrictEqual(tx.getSequenceHash(SIGHASH_NONE), ZERO)
        assert.deepStrictEqual(tx.getOutputsHash(SIGHASH_NONE, 0), ZERO)
      })

      it('clone starts with an empty cache', function () {
        var tx = buildTestTransaction(network, 3, 2)
        tx.getPrevoutHash(SIGHASH_ALL)
        var clone = tx.clone()
        assert.strictEqual(clone.__sighashCache, null)
        assert.deepStrictEqual(clone.getPrevoutHash(SIGHASH_ALL), tx.getPrevoutHash(SIGHASH_ALL))
      })
    })
  })

  describe('end to end: flux 2-of-2 P2SH multisig signing', function () {
    it('signatures made with warm cache verify against cold-instance sighashes', function () {
      var network = networks.flux
      var keyPair1 = deterministicKeyPair(1, network)
      var keyPair2 = deterministicKeyPair(2, network)
      var pubKeys = [keyPair1.getPublicKeyBuffer(), keyPair2.getPublicKeyBuffer()].sort(function (a, b) {
        return a.compare(b)
      })
      var redeemScript = btemplates.multisig.output.encode(2, pubKeys)
      var scriptPubKey = btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript))
      var numInputs = 20

      var txb = new TransactionBuilder(network)
      txb.setVersion(4)
      txb.tx.overwintered = 1
      txb.tx.versionGroupId = 0x892f2085
      var i
      for (i = 0; i < numInputs; i++) {
        txb.addInput(bcrypto.sha256(Buffer.from('utxo-' + i)).toString('hex'), 0)
      }
      txb.addOutput(scriptPubKey, VALUE * numInputs - 10000)

      // sign every input with both keys on the same (cache warm) builder
      for (i = 0; i < numInputs; i++) {
        txb.sign(i, keyPair1, redeemScript, SIGHASH_ALL, VALUE)
        txb.sign(i, keyPair2, redeemScript, SIGHASH_ALL, VALUE)
      }
      var tx = txb.build()

      // every signature must verify against the sighash recomputed from
      // scratch on a cold clone (empty cache) — exactly what network
      // consensus validation does
      for (i = 0; i < numInputs; i++) {
        var coldHash = tx.clone().hashForZcashSignature(i, redeemScript, VALUE, SIGHASH_ALL)
        var warmHash = tx.hashForZcashSignature(i, redeemScript, VALUE, SIGHASH_ALL)
        assert.deepStrictEqual(warmHash, coldHash)

        // scriptSig chunks: OP_0, sig1, sig2, redeemScript
        var scriptChunks = bscript.decompile(tx.ins[i].script)
        var signatures = scriptChunks.slice(1, -1) // strip leading OP_0 and trailing redeemScript
        assert.strictEqual(signatures.length, 2)
        signatures.forEach(function (signature) {
          var parsed = ECSignature.parseScriptSignature(signature)
          var verified = pubKeys.some(function (pubKey) {
            return ECPair.fromPublicKeyBuffer(pubKey, network).verify(coldHash, parsed.signature)
          })
          assert.strictEqual(verified, true)
        })
      }
    })

    it('fromTransaction + second-signer flow produces identical tx to single-pass signing', function () {
      var network = networks.flux
      var keyPair1 = deterministicKeyPair(3, network)
      var keyPair2 = deterministicKeyPair(4, network)
      var pubKeys = [keyPair1.getPublicKeyBuffer(), keyPair2.getPublicKeyBuffer()].sort(function (a, b) {
        return a.compare(b)
      })
      var redeemScript = btemplates.multisig.output.encode(2, pubKeys)
      var scriptPubKey = btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript))
      var numInputs = 10

      function makeBuilder () {
        var txb = new TransactionBuilder(network)
        txb.setVersion(4)
        txb.tx.overwintered = 1
        txb.tx.versionGroupId = 0x892f2085
        for (var i = 0; i < numInputs; i++) {
          txb.addInput(bcrypto.sha256(Buffer.from('utxo-rt-' + i)).toString('hex'), 0)
        }
        txb.addOutput(scriptPubKey, VALUE * numInputs - 10000)
        return txb
      }

      // single pass: both keys sign on one builder
      var single = makeBuilder()
      var i
      for (i = 0; i < numInputs; i++) {
        single.sign(i, keyPair1, redeemScript, SIGHASH_ALL, VALUE)
        single.sign(i, keyPair2, redeemScript, SIGHASH_ALL, VALUE)
      }
      var singleHex = single.build().toHex()

      // two pass (the SSP wallet -> key flow): first signer, serialize,
      // parse on the other side, second signer, finalise
      var first = makeBuilder()
      for (i = 0; i < numInputs; i++) {
        first.sign(i, keyPair1, redeemScript, SIGHASH_ALL, VALUE)
      }
      var partialHex = first.buildIncomplete().toHex()

      var second = TransactionBuilder.fromTransaction(Transaction.fromHex(partialHex, network), network)
      for (i = 0; i < numInputs; i++) {
        second.sign(i, keyPair2, redeemScript, SIGHASH_ALL, VALUE)
      }
      var twoPassHex = second.build().toHex()

      assert.strictEqual(twoPassHex, singleHex)
    })
  })
})
