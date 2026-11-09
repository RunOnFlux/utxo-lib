/* global describe, it */

var assert = require('assert')
var Buffer = require('safe-buffer').Buffer
var bcrypto = require('../src/crypto')
var bscript = require('../src/script')
var btemplates = require('../src/templates')
var ECPair = require('../src/ecpair')
var ECSignature = require('../src/ecsignature')
var Transaction = require('../src/transaction')
var TransactionBuilder = require('../src/transaction_builder')
var NETWORKS = require('../src/networks')
var zcashV5 = require('../src/zcash_v5')

// Official ZIP 244 vectors from zcash-test-vectors (zip_0244.py). Each row:
// tx, txid, auth_digest, amounts, script_pubkeys, transparent_input,
// sighash_shielded, sighash_all, sighash_none, sighash_single,
// sighash_all_anyone, sighash_none_anyone, sighash_single_anyone
var vectors = require('./fixtures/zcash/zip_0244.json').slice(2)

var NU7_BRANCH_ID = 0x77190ad9

describe('Zcash v5 (ZIP 225 / ZIP 244)', function () {
  describe('official ZIP 244 test vectors', function () {
    vectors.forEach(function (v, n) {
      var txHex = v[0]
      var txid = v[1]
      var amounts = v[3]
      var scripts = v[4]
      var tin = v[5]
      var expected = { 0x01: v[7], 0x02: v[8], 0x03: v[9], 0x81: v[10], 0x82: v[11], 0x83: v[12] }

      it('vector ' + n + ': parses, re-serializes byte for byte and computes the txid', function () {
        var tx = Transaction.fromHex(txHex, NETWORKS.zcash)
        assert.strictEqual(tx.version, 5)
        assert.strictEqual(tx.isZcashV5(), true)
        assert.strictEqual(tx.toHex(), txHex)
        assert.strictEqual(tx.byteLength(), txHex.length / 2)
        // vectors store the digest in internal byte order
        assert.strictEqual(tx.getHash().toString('hex'), txid)
        assert.strictEqual(tx.getId(), Buffer.from(txid, 'hex').reverse().toString('hex'))
        assert.strictEqual(tx.clone().toHex(), txHex)
      })

      if (tin === null || tin === undefined) return

      it('vector ' + n + ': transparent signature digests for every hash type', function () {
        var tx = Transaction.fromHex(txHex, NETWORKS.zcash)
        tx.setZip244Prevouts(amounts.map(function (a, i) {
          return { value: a, script: Buffer.from(scripts[i], 'hex') }
        }))
        Object.keys(expected).forEach(function (ht) {
          if (expected[ht] === null) return
          var got = tx.hashForZcashSignature(tin, Buffer.alloc(0), amounts[tin], Number(ht))
          assert.strictEqual(got.toString('hex'), expected[ht], 'hash type 0x' + Number(ht).toString(16))
        })
      })
    })
  })

  describe('2-of-2 P2SH multisig, signed in two steps like SSP wallet + key', function () {
    var network = NETWORKS.zcash
    var walletKey = ECPair.fromWIF('L1Knwj9W3qK3qMKdTvmg3VfzUs3ij2LETTFhxza9LfD5dngnoLG1', network)
    var keyKey = ECPair.fromWIF('KwcN2pT3wnRAurhy7qMczzbkpY5nXMW2ubh696UBc1bcwctTx26z', network)
    var pubKeys = [walletKey.getPublicKeyBuffer(), keyKey.getPublicKeyBuffer()]
    var redeemScript = btemplates.multisig.output.encode(2, pubKeys)
    var scriptPubKey = btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript))
    var otherOut = btemplates.pubKeyHash.output.encode(bcrypto.hash160(pubKeys[0]))
    var values = [150000, 260000]

    function newBuilder () {
      var txb = new TransactionBuilder(network, 1000)
      txb.setVersion(Transaction.ZCASH_NU5_VERSION)
      txb.setExpiryHeight(3543500)
      txb.addInput('aa'.repeat(32), 0)
      txb.addInput('bb'.repeat(32), 3)
      txb.addOutput(otherOut, 300000)
      txb.addOutput(scriptPubKey, 100000)
      return txb
    }
    function prevouts () {
      return values.map(function (value) { return { value: value, script: scriptPubKey } })
    }

    it('builds a v5 transaction with the NU7 branch id', function () {
      var tx = newBuilder().buildIncomplete()
      assert.strictEqual(tx.version, 5)
      assert.strictEqual(tx.overwintered, 1)
      assert.strictEqual(tx.versionGroupId, 0x26A7270A)
      assert.strictEqual(tx.consensusBranchId, NU7_BRANCH_ID)
      assert.strictEqual(tx.toHex().slice(0, 24), '050000800a27a726d90a1977')
      var parsed = Transaction.fromHex(tx.toHex(), network)
      assert.strictEqual(parsed.toHex(), tx.toHex())
    })

    it('signs with both keys; every signature verifies against the ZIP 244 digest', function () {
      var txb = newBuilder()
      txb.setPrevouts(prevouts())
      values.forEach(function (value, i) {
        txb.sign(i, walletKey, redeemScript, Transaction.SIGHASH_ALL, value)
      })
      var partialHex = txb.buildIncomplete().toHex()

      // the key side starts from the wallet's partially signed hex
      var partial = Transaction.fromHex(partialHex, network)
      var txb2 = TransactionBuilder.fromTransaction(partial, network)
      txb2.setPrevouts(prevouts())
      values.forEach(function (value, i) {
        txb2.sign(i, keyKey, redeemScript, Transaction.SIGHASH_ALL, value)
      })
      var final = txb2.build()
      assert.strictEqual(final.version, 5)

      final.setZip244Prevouts(prevouts())
      final.ins.forEach(function (input, i) {
        var chunks = bscript.decompile(input.script)
        // OP_0 <walletSig> <keySig> <redeemScript>
        assert.strictEqual(chunks.length, 4)
        assert.ok(Buffer.from(chunks[3]).equals(redeemScript))
        var hash = final.hashForZcashSignature(i, redeemScript, values[i], Transaction.SIGHASH_ALL)
        ;[walletKey, keyKey].forEach(function (k, j) {
          var parsed = ECSignature.parseScriptSignature(chunks[1 + j])
          assert.strictEqual(parsed.hashType, Transaction.SIGHASH_ALL)
          assert.ok(k.verify(hash, parsed.signature), 'signature ' + j + ' of input ' + i)
        })
      })
      assert.strictEqual(final.getId().length, 64)
    })

    it('a signature commits to the other inputs\' values', function () {
      var txb = newBuilder()
      txb.setPrevouts(prevouts())
      txb.sign(0, walletKey, redeemScript, Transaction.SIGHASH_ALL, values[0])
      var tx = txb.buildIncomplete()
      var sig = ECSignature.parseScriptSignature(bscript.decompile(tx.ins[0].script)[1])

      tx.setZip244Prevouts([{ value: values[0], script: scriptPubKey }, { value: values[1] - 1, script: scriptPubKey }])
      var lyingHash = tx.hashForZcashSignature(0, redeemScript, values[0], Transaction.SIGHASH_ALL)
      assert.strictEqual(walletKey.verify(lyingHash, sig.signature), false)
    })

    it('refuses to sign without prevouts', function () {
      var txb = newBuilder()
      assert.throws(function () {
        txb.sign(0, walletKey, redeemScript, Transaction.SIGHASH_ALL, values[0])
      }, /setPrevouts/)
    })

    it('refuses a value that differs from the prevouts', function () {
      var txb = newBuilder()
      txb.setPrevouts(prevouts())
      assert.throws(function () {
        txb.sign(0, walletKey, redeemScript, Transaction.SIGHASH_ALL, values[0] + 1)
      }, /does not match the prevouts/)
    })

    it('refuses prevouts whose scriptPubKey is not the input\'s', function () {
      var txb = newBuilder()
      txb.setPrevouts(values.map(function (value) { return { value: value, script: otherOut } }))
      assert.throws(function () {
        txb.sign(0, walletKey, redeemScript, Transaction.SIGHASH_ALL, values[0])
      }, /script does not match the prevouts/)
    })

    it('refuses prevouts of the wrong length', function () {
      var txb = newBuilder()
      assert.throws(function () {
        txb.setPrevouts([{ value: values[0], script: scriptPubKey }])
      }, /Expected 2 prevouts/)
    })

    it('refuses an undefined hash type', function () {
      var txb = newBuilder()
      txb.setPrevouts(prevouts())
      assert.throws(function () {
        txb.sign(0, walletKey, redeemScript, 0x41, values[0])
      }, /Invalid hash type/)
    })
  })

  describe('guards', function () {
    var network = NETWORKS.zcash
    var v = vectors.find(function (r) { return r[5] !== null && r[5] !== undefined })
    var prevouts = v[3].map(function (a, i) { return { value: a, script: Buffer.from(v[4][i], 'hex') } })

    it('hashForZcashSignature needs prevouts, the matching value and a valid index', function () {
      var tx = Transaction.fromHex(v[0], network)
      assert.throws(function () {
        tx.hashForZcashSignature(v[5], Buffer.alloc(0), v[3][v[5]], 1)
      }, /setZip244Prevouts/)
      tx.setZip244Prevouts(prevouts)
      assert.throws(function () {
        tx.hashForZcashSignature(v[5], Buffer.alloc(0), v[3][v[5]] + 1, 1)
      }, /does not match the prevouts/)
      assert.throws(function () {
        tx.hashForZcashSignature(tx.ins.length, Buffer.alloc(0), 1, 1)
      }, /out of range/)
    })

    it('SIGHASH_SINGLE needs a corresponding output', function () {
      var txb = new TransactionBuilder(network)
      txb.setVersion(5)
      txb.addInput('aa'.repeat(32), 0)
      txb.addInput('bb'.repeat(32), 0)
      txb.addOutput(Buffer.from('76a914' + '11'.repeat(20) + '88ac', 'hex'), 1000)
      var tx = txb.buildIncomplete()
      var script = Buffer.from('a914' + '22'.repeat(20) + '87', 'hex')
      tx.setZip244Prevouts([{ value: 5000, script: script }, { value: 5000, script: script }])
      assert.throws(function () {
        tx.hashForZcashSignature(1, script, 5000, Transaction.SIGHASH_SINGLE)
      }, /corresponding output/)
    })

    it('setZip244Prevouts is v5 only', function () {
      var txb = new TransactionBuilder(network)
      txb.setVersion(4)
      txb.setVersionGroupId(0x892F2085)
      txb.addInput('aa'.repeat(32), 0)
      assert.throws(function () {
        txb.setPrevouts([{ value: 1, script: Buffer.alloc(1) }])
      }, /only for Zcash v5/)
      assert.throws(function () { txb.setConsensusBranchId(1) }, /only be set for Zcash v5/)
    })

    it('setVersion refuses v5 without overwinter, unknown versions and signed inputs', function () {
      assert.throws(function () { new TransactionBuilder(network).setVersion(5, false) }, /Unsupported/)
      assert.throws(function () { new TransactionBuilder(network).setVersion(6) }, /Unsupported/)
    })

    it('signatureDigest refuses a prevouts list that does not cover every input', function () {
      var tx = Transaction.fromHex(v[0], network)
      assert.throws(function () {
        zcashV5.signatureDigest(tx, v[5], 1, prevouts.slice(1))
      }, /every input/)
    })

    it('setVersion refuses to change the version of a signed transaction', function () {
      var key = ECPair.makeRandom({ network: network })
      var script = btemplates.pubKeyHash.output.encode(bcrypto.hash160(key.getPublicKeyBuffer()))
      var txb = new TransactionBuilder(network)
      txb.setVersion(4)
      txb.setVersionGroupId(0x892F2085)
      txb.addInput('aa'.repeat(32), 0, undefined, script)
      txb.addOutput(script, 1000)
      txb.sign(0, key, null, Transaction.SIGHASH_ALL, 2000)
      assert.throws(function () { txb.setVersion(5) }, /invalidate signatures/)
    })

    it('rejects a v5 header without the overwinter flag, and trailing data', function () {
      var bytes = Buffer.from(v[0], 'hex')
      var noOverwinter = Buffer.from(bytes)
      noOverwinter.writeUInt32LE(5, 0)
      assert.throws(function () { Transaction.fromBuffer(noOverwinter, network) }, /Unsupported Zcash transaction/)
      var trailing = Buffer.concat([bytes, Buffer.from([0])])
      assert.throws(function () { Transaction.fromBuffer(trailing, network) }, /unexpected data/)
      assert.strictEqual(Transaction.fromBuffer(trailing, network, true).toHex(), v[0])
    })

    it('rejects an unknown v5 version group id', function () {
      var bytes = Buffer.from(v[0], 'hex')
      bytes.writeUInt32LE(0x12345678, 4)
      assert.throws(function () { Transaction.fromBuffer(bytes, network) }, /version group id/)
    })

    it('serializes into a caller buffer at an offset', function () {
      var tx = Transaction.fromHex(v[0], network)
      var buf = Buffer.alloc(tx.byteLength() + 3)
      var out = tx.toBuffer(buf, 3)
      assert.strictEqual(out.toString('hex'), v[0])
      var exact = Buffer.alloc(tx.byteLength())
      assert.strictEqual(tx.toBuffer(exact).toString('hex'), v[0])
    })
  })

  describe('scope', function () {
    it('Flux (a Zcash-derived network) has no v5', function () {
      var txb = new TransactionBuilder(NETWORKS.flux)
      assert.throws(function () { txb.setVersion(5) }, /Unsupported Zcash transaction/)
    })

    it('fromTransaction refuses v5 transactions with shielded components', function () {
      var shielded = vectors.find(function (v) {
        var tx = Transaction.fromHex(v[0], NETWORKS.zcash)
        return tx.sapling.spends.length + tx.sapling.outputs.length + tx.orchard.actions.length > 0
      })
      var tx = Transaction.fromHex(shielded[0], NETWORKS.zcash)
      assert.throws(function () {
        TransactionBuilder.fromTransaction(tx, NETWORKS.zcash)
      }, /shielded components are not supported/)
    })

    it('v4 Zcash transactions still parse and serialize unchanged', function () {
      var txb = new TransactionBuilder(NETWORKS.zcash)
      txb.setVersion(Transaction.ZCASH_SAPLING_VERSION)
      txb.setVersionGroupId(0x892F2085)
      txb.addInput('cc'.repeat(32), 1)
      txb.addOutput(Buffer.from('76a914' + '11'.repeat(20) + '88ac', 'hex'), 1000)
      var hex = txb.buildIncomplete().toHex()
      assert.strictEqual(hex.slice(0, 8), '04000080')
      assert.strictEqual(Transaction.fromHex(hex, NETWORKS.zcash).toHex(), hex)
    })
  })
})
