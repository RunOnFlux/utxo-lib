/* global describe, it */

// Regression tests for the 2026-10 security review:
// - UTXO-1 (lib part): TransactionBuilder.sign must refuse a caller-supplied
//   witnessScript/redeemScript that the (already expanded) input does not
//   commit to, instead of silently signing the foreign script.
// - UTXO-7: the absurd-fee backstop must use real input values and must not
//   truncate values >= 2^32 satoshi.

var assert = require('assert')
var bcrypto = require('../src/crypto')
var btemplates = require('../src/templates')
var BigInteger = require('bigi')
var ECPair = require('../src/ecpair')
var Transaction = require('../src/transaction')
var TransactionBuilder = require('../src/transaction_builder')
var NETWORKS = require('../src/networks')

var network = NETWORKS.bitcoin

function keyFromInt (n) {
  return new ECPair(BigInteger.valueOf(n), null, { network: network, compressed: true })
}

var walletKey = keyFromInt(1001)
var keyKey = keyFromInt(1002)
var attackerKey = keyFromInt(1003)

function multisig (m, keys) {
  return btemplates.multisig.output.encode(m, keys.map(function (k) { return k.getPublicKeyBuffer() }))
}
function p2wsh (witnessScript) {
  return btemplates.witnessScriptHash.output.encode(bcrypto.sha256(witnessScript))
}
function p2sh (redeemScript) {
  return btemplates.scriptHash.output.encode(bcrypto.hash160(redeemScript))
}

var TXID_A = 'aa'.repeat(32)
var TXID_B = 'bb'.repeat(32)

// The honest vault script: 2-of-2 [wallet, key] (what the key derives itself)
var vaultWitnessScript = multisig(2, [walletKey, keyKey])
// The attacker's script: 1-of-2 [attacker, key]; contains the key's pubkey so
// the key can sign it, but the attacker can spend it alone.
var attackerWitnessScript = multisig(1, [attackerKey, keyKey])

describe('TransactionBuilder script consistency (UTXO-1)', function () {
  it('honest P2WSH 2-of-2 flow still signs and builds', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 90000)
    txb.sign(0, walletKey, undefined, Transaction.SIGHASH_ALL, 100000, vaultWitnessScript)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    txbKey.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 100000, vaultWitnessScript)
    var signed = txbKey.buildIncomplete().toHex()

    var final = TransactionBuilder.fromTransaction(Transaction.fromHex(signed, network), network).build()
    assert.strictEqual(final.ins[0].witness.length, 4) // OP_0 placeholder, 2 sigs, script
    assert.ok(final.ins[0].witness[3].equals(vaultWitnessScript))
  })

  it('refuses to sign a P2WSH input whose embedded witnessScript differs from the caller\'s', function () {
    // compromised wallet: input 0 is attacker dust at P2WSH(1-of-2 [attacker, key]),
    // input 1 is the user's real vault UTXO
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addInput(TXID_B, 0)
    txb.addOutput(p2wsh(attackerWitnessScript), 99000000) // hidden as "change"
    txb.addOutput(p2wsh(vaultWitnessScript), 10000)
    // the wallet prepares input 0 with the attacker script (attacker signs its slot)
    txb.sign(0, attackerKey, undefined, Transaction.SIGHASH_ALL, 1000, attackerWitnessScript)
    txb.sign(1, walletKey, undefined, Transaction.SIGHASH_ALL, 99100000, vaultWitnessScript)
    var partial = txb.buildIncomplete().toHex()

    // the key signs every input with its own derived witnessScript
    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.ok(txbKey.inputs[0].witnessScript.equals(attackerWitnessScript))
    assert.throws(function () {
      txbKey.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 1000, vaultWitnessScript)
    }, /Inconsistent witnessScript/)
    // no signature was added to the foreign input
    assert.ok(txbKey.inputs[0].signatures.every(function (s, i) {
      return !s || !txbKey.inputs[0].pubKeys[i].equals(keyKey.getPublicKeyBuffer())
    }))
    // the real vault input still signs
    txbKey.sign(1, keyKey, undefined, Transaction.SIGHASH_ALL, 99100000, vaultWitnessScript)
  })

  it('refuses a witnessScript for an input that was expanded as legacy P2SH', function () {
    // compromised wallet wraps the attacker script as legacy P2SH instead of P2WSH
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 1000)
    txb.sign(0, attackerKey, attackerWitnessScript, Transaction.SIGHASH_ALL, 2000)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.strictEqual(txbKey.inputs[0].witnessScript, undefined)
    assert.throws(function () {
      txbKey.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    }, /Inconsistent witnessScript/)
  })

  it('refuses a redeemScript for an input that was expanded as bare P2WSH', function () {
    // P2SH-chain signer (passes only a redeemScript) handed a bare P2WSH input
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2sh(vaultWitnessScript), 1000)
    txb.sign(0, attackerKey, undefined, Transaction.SIGHASH_ALL, 2000, attackerWitnessScript)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.throws(function () {
      txbKey.sign(0, keyKey, vaultWitnessScript, Transaction.SIGHASH_ALL, 2000)
    }, /Inconsistent redeemScript/)
  })

  it('still refuses an inconsistent redeemScript (existing behaviour)', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2sh(vaultWitnessScript), 1000)
    txb.sign(0, attackerKey, attackerWitnessScript, Transaction.SIGHASH_ALL, 2000)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.throws(function () {
      txbKey.sign(0, keyKey, vaultWitnessScript, Transaction.SIGHASH_ALL, 2000)
    }, /Inconsistent redeemScript/)
  })

  it('refuses a witnessValue different from the value already recorded for the input', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 1000)
    txb.sign(0, walletKey, undefined, Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    assert.throws(function () {
      txb.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 3000, vaultWitnessScript)
    }, /Input didn't match witnessValue/)
  })

  it('refuses redeemScript + witnessScript (P2SH-P2WSH) for a bare P2WSH input', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 1000)
    txb.sign(0, walletKey, undefined, Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.throws(function () {
      txbKey.sign(0, keyKey, p2wsh(vaultWitnessScript), Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    }, /Inconsistent redeemScript/)
  })

  // Documented limitation (see CHANGELOG 1.0.6): the wrapping check is
  // one-way. An input that carries a P2SH wrapper the caller did not pass is
  // NOT refused, because the BIP143 sighash does not commit to the wrapper.
  // Callers must check each input's prevout scriptPubKey themselves. If this
  // test starts failing because the library became stricter, update the
  // CHANGELOG note instead of deleting the test.
  it('does not detect an extra P2SH wrapper the caller did not pass (one-way check)', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 1000)
    txb.sign(0, walletKey, p2wsh(vaultWitnessScript), Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.ok(txbKey.inputs[0].redeemScript !== undefined)
    assert.doesNotThrow(function () {
      txbKey.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 2000, vaultWitnessScript)
    })
  })
})

describe('TransactionBuilder absurd-fee check (UTXO-7)', function () {
  it('does not truncate input values >= 2^32 satoshi', function () {
    // 2^32 + 10000 sat in, 10000 sat out: the fee is 2^32 sat (~42.9 BTC).
    // `value >>> 0` used to truncate the input to 10000 sat (fee 0).
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 10000)
    txb.sign(0, walletKey, undefined, Transaction.SIGHASH_ALL, 4294967296 + 10000, vaultWitnessScript)
    txb.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 4294967296 + 10000, vaultWitnessScript)
    assert.throws(function () {
      txb.build()
    }, /Transaction has absurd fees/)
  })

  it('uses the input values supplied to sign() on a builder rebuilt from a partially signed tx', function () {
    // legacy P2SH 2-of-2: the second signer imports the partially signed tx, so
    // the input is already expanded; its sign() value must still feed the check
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2sh(vaultWitnessScript), 1000)
    txb.sign(0, walletKey, vaultWitnessScript, Transaction.SIGHASH_ALL)
    var partial = txb.buildIncomplete().toHex()

    var txbKey = TransactionBuilder.fromTransaction(Transaction.fromHex(partial, network), network)
    assert.strictEqual(txbKey.inputs[0].value, undefined)
    txbKey.sign(0, keyKey, vaultWitnessScript, Transaction.SIGHASH_ALL, 100000000)
    assert.strictEqual(txbKey.inputs[0].value, 100000000)
    assert.throws(function () {
      txbKey.build()
    }, /Transaction has absurd fees/)
  })

  it('does not fire when input values are unknown (lower bound only)', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2sh(vaultWitnessScript), 1000)
    txb.sign(0, walletKey, vaultWitnessScript, Transaction.SIGHASH_ALL)
    txb.sign(0, keyKey, vaultWitnessScript, Transaction.SIGHASH_ALL)
    var signed = txb.buildIncomplete().toHex()
    var rebuilt = TransactionBuilder.fromTransaction(Transaction.fromHex(signed, network), network)
    assert.doesNotThrow(function () { rebuilt.build() })
  })

  it('does not fire for a normal fee', function () {
    var txb = new TransactionBuilder(network)
    txb.addInput(TXID_A, 0)
    txb.addOutput(p2wsh(vaultWitnessScript), 4294967296)
    txb.sign(0, walletKey, undefined, Transaction.SIGHASH_ALL, 4294967296 + 20000, vaultWitnessScript)
    txb.sign(0, keyKey, undefined, Transaction.SIGHASH_ALL, 4294967296 + 20000, vaultWitnessScript)
    assert.doesNotThrow(function () { txb.build() })
  })
})
