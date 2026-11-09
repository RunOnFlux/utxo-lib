/**
 * Zcash v5 transactions (NU5 and later): ZIP 225 encoding and ZIP 244 digests.
 *
 * NU7 (mainnet block 3,543,405, Nov 2026) made v4 transactions invalid
 * (ZIP 2003), so ZEC spends must use this format. Flux and other Zcash-derived
 * networks keep using v4 and never reach this module.
 *
 * Signing is supported for transparent inputs only. Sapling and Orchard bundles
 * are parsed, re-serialized byte for byte and committed to by the txid and the
 * signature digest, so transactions carrying them can be read and identified,
 * but the library never creates shielded components.
 *
 * https://zips.z.cash/zip-0225
 * https://zips.z.cash/zip-0244
 */
var Buffer = require('safe-buffer').Buffer
var BufferWriter = require('./bufferWriter')
var varuint = require('varuint-bitcoin')
var blake2b = require('blake2b')

var VERSION = 5
var VERSION_GROUP_ID = 0x26A7270A

var SAPLING_SPEND_SIZE = 32 * 3 // cv, nullifier, rk
var SAPLING_OUTPUT_SIZE = 32 * 3 + 580 + 80 // cv, cmu, ephemeralKey, enc, out
var ORCHARD_ACTION_SIZE = 32 * 5 + 580 + 80 // cv, nullifier, rk, cmx, ephemeralKey, enc, out
var GROTH_PROOF_SIZE = 192
var SIG_SIZE = 64

var SIGHASH_ALL = 0x01
var SIGHASH_NONE = 0x02
var SIGHASH_SINGLE = 0x03
var SIGHASH_ANYONECANPAY = 0x80
var VALID_HASH_TYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

function blake (personalization, data) {
  var out = Buffer.alloc(32)
  var p = Buffer.isBuffer(personalization) ? personalization : Buffer.from(personalization)
  return Buffer.from(blake2b(32, null, null, p).update(data || Buffer.alloc(0)).digest(out))
}

function varSliceSize (slice) {
  return varuint.encodingLength(slice.length) + slice.length
}

function emptySapling () {
  return {
    spends: [],
    outputs: [],
    valueBalance: Buffer.alloc(8),
    anchor: null,
    spendProofs: [],
    spendAuthSigs: [],
    outputProofs: [],
    bindingSig: null
  }
}

function emptyOrchard () {
  return {
    actions: [],
    flags: 0,
    valueBalance: Buffer.alloc(8),
    anchor: null,
    proofs: Buffer.alloc(0),
    spendAuthSigs: [],
    bindingSig: null
  }
}

function hasSapling (tx) {
  return tx.sapling.spends.length + tx.sapling.outputs.length > 0
}

function hasOrchard (tx) {
  return tx.orchard.actions.length > 0
}

/**
 * Read the v5 body that follows the 4-byte header. Returns the new offset.
 * `reader` exposes the closures of Transaction.fromBuffer.
 */
function readBody (tx, r) {
  var i
  tx.versionGroupId = r.readUInt32()
  if (tx.versionGroupId !== VERSION_GROUP_ID) {
    throw new Error('Unsupported Zcash v5 version group id')
  }
  tx.consensusBranchId = r.readUInt32()
  tx.locktime = r.readUInt32()
  tx.expiryHeight = r.readUInt32()

  var vinLen = r.readVarInt()
  for (i = 0; i < vinLen; ++i) {
    tx.ins.push({
      hash: r.readSlice(32),
      index: r.readUInt32(),
      script: r.readVarSlice(),
      sequence: r.readUInt32(),
      witness: []
    })
  }
  var voutLen = r.readVarInt()
  for (i = 0; i < voutLen; ++i) {
    tx.outs.push({
      value: r.readUInt64(),
      script: r.readVarSlice()
    })
  }

  var sapling = emptySapling()
  var nSpends = r.readVarInt()
  for (i = 0; i < nSpends; ++i) {
    sapling.spends.push({ cv: r.readSlice(32), nullifier: r.readSlice(32), rk: r.readSlice(32) })
  }
  var nOutputs = r.readVarInt()
  for (i = 0; i < nOutputs; ++i) {
    sapling.outputs.push({
      cv: r.readSlice(32),
      cmu: r.readSlice(32),
      ephemeralKey: r.readSlice(32),
      encCiphertext: r.readSlice(580),
      outCiphertext: r.readSlice(80)
    })
  }
  if (nSpends + nOutputs > 0) {
    sapling.valueBalance = r.readSlice(8)
  }
  if (nSpends > 0) {
    sapling.anchor = r.readSlice(32)
  }
  for (i = 0; i < nSpends; ++i) sapling.spendProofs.push(r.readSlice(GROTH_PROOF_SIZE))
  for (i = 0; i < nSpends; ++i) sapling.spendAuthSigs.push(r.readSlice(SIG_SIZE))
  for (i = 0; i < nOutputs; ++i) sapling.outputProofs.push(r.readSlice(GROTH_PROOF_SIZE))
  if (nSpends + nOutputs > 0) {
    sapling.bindingSig = r.readSlice(SIG_SIZE)
  }
  tx.sapling = sapling

  var orchard = emptyOrchard()
  var nActions = r.readVarInt()
  for (i = 0; i < nActions; ++i) {
    orchard.actions.push({
      cv: r.readSlice(32),
      nullifier: r.readSlice(32),
      rk: r.readSlice(32),
      cmx: r.readSlice(32),
      ephemeralKey: r.readSlice(32),
      encCiphertext: r.readSlice(580),
      outCiphertext: r.readSlice(80)
    })
  }
  if (nActions > 0) {
    orchard.flags = r.readUInt8()
    orchard.valueBalance = r.readSlice(8)
    orchard.anchor = r.readSlice(32)
    orchard.proofs = r.readVarSlice()
    for (i = 0; i < nActions; ++i) orchard.spendAuthSigs.push(r.readSlice(SIG_SIZE))
    orchard.bindingSig = r.readSlice(SIG_SIZE)
  }
  tx.orchard = orchard
}

function byteLength (tx) {
  var sapling = tx.sapling
  var orchard = tx.orchard
  var nSpends = sapling.spends.length
  var nOutputs = sapling.outputs.length
  var nActions = orchard.actions.length
  var n = 4 * 5 // header, nVersionGroupId, nConsensusBranchId, lock_time, nExpiryHeight
  n += varuint.encodingLength(tx.ins.length)
  n += tx.ins.reduce(function (sum, input) { return sum + 40 + varSliceSize(input.script) }, 0)
  n += varuint.encodingLength(tx.outs.length)
  n += tx.outs.reduce(function (sum, output) { return sum + 8 + varSliceSize(output.script) }, 0)
  n += varuint.encodingLength(nSpends) + nSpends * SAPLING_SPEND_SIZE
  n += varuint.encodingLength(nOutputs) + nOutputs * SAPLING_OUTPUT_SIZE
  if (nSpends + nOutputs > 0) n += 8
  if (nSpends > 0) n += 32
  n += nSpends * (GROTH_PROOF_SIZE + SIG_SIZE) + nOutputs * GROTH_PROOF_SIZE
  if (nSpends + nOutputs > 0) n += SIG_SIZE
  n += varuint.encodingLength(nActions) + nActions * ORCHARD_ACTION_SIZE
  if (nActions > 0) {
    n += 1 + 8 + 32 + varSliceSize(orchard.proofs) + nActions * SIG_SIZE + SIG_SIZE
  }
  return n
}

function writeTx (tx, w) {
  var sapling = tx.sapling
  var orchard = tx.orchard
  w.writeInt32(tx.getHeader())
  w.writeUInt32(tx.versionGroupId)
  w.writeUInt32(tx.consensusBranchId)
  w.writeUInt32(tx.locktime)
  w.writeUInt32(tx.expiryHeight)

  w.writeVarInt(tx.ins.length)
  tx.ins.forEach(function (txIn) {
    w.writeSlice(txIn.hash)
    w.writeUInt32(txIn.index)
    w.writeVarSlice(txIn.script)
    w.writeUInt32(txIn.sequence)
  })
  w.writeVarInt(tx.outs.length)
  tx.outs.forEach(function (txOut) {
    w.writeUInt64(txOut.value)
    w.writeVarSlice(txOut.script)
  })

  var nSpends = sapling.spends.length
  var nOutputs = sapling.outputs.length
  w.writeVarInt(nSpends)
  sapling.spends.forEach(function (s) {
    w.writeSlice(s.cv)
    w.writeSlice(s.nullifier)
    w.writeSlice(s.rk)
  })
  w.writeVarInt(nOutputs)
  sapling.outputs.forEach(function (o) {
    w.writeSlice(o.cv)
    w.writeSlice(o.cmu)
    w.writeSlice(o.ephemeralKey)
    w.writeSlice(o.encCiphertext)
    w.writeSlice(o.outCiphertext)
  })
  if (nSpends + nOutputs > 0) w.writeSlice(sapling.valueBalance)
  if (nSpends > 0) w.writeSlice(sapling.anchor)
  sapling.spendProofs.forEach(function (p) { w.writeSlice(p) })
  sapling.spendAuthSigs.forEach(function (s) { w.writeSlice(s) })
  sapling.outputProofs.forEach(function (p) { w.writeSlice(p) })
  if (nSpends + nOutputs > 0) w.writeSlice(sapling.bindingSig)

  var nActions = orchard.actions.length
  w.writeVarInt(nActions)
  orchard.actions.forEach(function (a) {
    w.writeSlice(a.cv)
    w.writeSlice(a.nullifier)
    w.writeSlice(a.rk)
    w.writeSlice(a.cmx)
    w.writeSlice(a.ephemeralKey)
    w.writeSlice(a.encCiphertext)
    w.writeSlice(a.outCiphertext)
  })
  if (nActions > 0) {
    w.writeUInt8(orchard.flags)
    w.writeSlice(orchard.valueBalance)
    w.writeSlice(orchard.anchor)
    w.writeVarSlice(orchard.proofs)
    orchard.spendAuthSigs.forEach(function (s) { w.writeSlice(s) })
    w.writeSlice(orchard.bindingSig)
  }
}

function cloneInto (from, to) {
  to.consensusBranchId = from.consensusBranchId
  // Shielded bundles are immutable buffers; a shallow copy of the containers
  // is enough to keep the clone independent of later list edits.
  var s = from.sapling
  to.sapling = {
    spends: s.spends.slice(),
    outputs: s.outputs.slice(),
    valueBalance: s.valueBalance,
    anchor: s.anchor,
    spendProofs: s.spendProofs.slice(),
    spendAuthSigs: s.spendAuthSigs.slice(),
    outputProofs: s.outputProofs.slice(),
    bindingSig: s.bindingSig
  }
  var o = from.orchard
  to.orchard = {
    actions: o.actions.slice(),
    flags: o.flags,
    valueBalance: o.valueBalance,
    anchor: o.anchor,
    proofs: o.proofs,
    spendAuthSigs: o.spendAuthSigs.slice(),
    bindingSig: o.bindingSig
  }
  to.__zip244Prevouts = from.__zip244Prevouts
}

// ---------------------------------------------------------------------------
// ZIP 244 digests
// ---------------------------------------------------------------------------

function headerDigest (tx) {
  var w = new BufferWriter(20)
  w.writeInt32(tx.getHeader())
  w.writeUInt32(tx.versionGroupId)
  w.writeUInt32(tx.consensusBranchId)
  w.writeUInt32(tx.locktime)
  w.writeUInt32(tx.expiryHeight)
  return blake('ZTxIdHeadersHash', w.getBuffer())
}

function prevoutsDigest (ins) {
  var w = new BufferWriter(36 * ins.length)
  ins.forEach(function (txIn) {
    w.writeSlice(txIn.hash)
    w.writeUInt32(txIn.index)
  })
  return blake('ZTxIdPrevoutHash', w.getBuffer())
}

function sequenceDigest (ins) {
  var w = new BufferWriter(4 * ins.length)
  ins.forEach(function (txIn) { w.writeUInt32(txIn.sequence) })
  return blake('ZTxIdSequencHash', w.getBuffer())
}

function outputsDigest (outs) {
  var size = outs.reduce(function (sum, o) { return sum + 8 + varSliceSize(o.script) }, 0)
  var w = new BufferWriter(size)
  outs.forEach(function (o) {
    w.writeUInt64(o.value)
    w.writeVarSlice(o.script)
  })
  return blake('ZTxIdOutputsHash', w.getBuffer())
}

function amountsDigest (prevouts) {
  var w = new BufferWriter(8 * prevouts.length)
  prevouts.forEach(function (p) { w.writeUInt64(p.value) })
  return blake('ZTxTrAmountsHash', w.getBuffer())
}

function scriptPubKeysDigest (prevouts) {
  var size = prevouts.reduce(function (sum, p) { return sum + varSliceSize(p.script) }, 0)
  var w = new BufferWriter(size)
  prevouts.forEach(function (p) { w.writeVarSlice(p.script) })
  return blake('ZTxTrScriptsHash', w.getBuffer())
}

function transparentTxidDigest (tx) {
  if (tx.ins.length === 0 && tx.outs.length === 0) {
    return blake('ZTxIdTranspaHash')
  }
  return blake('ZTxIdTranspaHash', Buffer.concat([
    cached(tx, 'prevouts', function () { return prevoutsDigest(tx.ins) }),
    cached(tx, 'sequence', function () { return sequenceDigest(tx.ins) }),
    cached(tx, 'outputs', function () { return outputsDigest(tx.outs) })
  ]))
}

function concat (parts) { return Buffer.concat(parts) }

function saplingDigest (tx) {
  if (!hasSapling(tx)) return blake('ZTxIdSaplingHash')
  var s = tx.sapling
  var spends
  if (s.spends.length > 0) {
    var compact = blake('ZTxIdSSpendCHash', concat(s.spends.map(function (x) { return x.nullifier })))
    var noncompact = blake('ZTxIdSSpendNHash', concat(s.spends.map(function (x) {
      return concat([x.cv, s.anchor, x.rk])
    })))
    spends = blake('ZTxIdSSpendsHash', concat([compact, noncompact]))
  } else {
    spends = blake('ZTxIdSSpendsHash')
  }
  var outputs
  if (s.outputs.length > 0) {
    var oc = blake('ZTxIdSOutC__Hash', concat(s.outputs.map(function (x) {
      return concat([x.cmu, x.ephemeralKey, x.encCiphertext.slice(0, 52)])
    })))
    var om = blake('ZTxIdSOutM__Hash', concat(s.outputs.map(function (x) {
      return x.encCiphertext.slice(52, 564)
    })))
    var on = blake('ZTxIdSOutN__Hash', concat(s.outputs.map(function (x) {
      return concat([x.cv, x.encCiphertext.slice(564), x.outCiphertext])
    })))
    outputs = blake('ZTxIdSOutputHash', concat([oc, om, on]))
  } else {
    outputs = blake('ZTxIdSOutputHash')
  }
  return blake('ZTxIdSaplingHash', concat([spends, outputs, s.valueBalance]))
}

function orchardDigest (tx) {
  if (!hasOrchard(tx)) return blake('ZTxIdOrchardHash')
  var o = tx.orchard
  var compact = blake('ZTxIdOrcActCHash', concat(o.actions.map(function (a) {
    return concat([a.nullifier, a.cmx, a.ephemeralKey, a.encCiphertext.slice(0, 52)])
  })))
  var memos = blake('ZTxIdOrcActMHash', concat(o.actions.map(function (a) {
    return a.encCiphertext.slice(52, 564)
  })))
  var noncompact = blake('ZTxIdOrcActNHash', concat(o.actions.map(function (a) {
    return concat([a.cv, a.rk, a.encCiphertext.slice(564), a.outCiphertext])
  })))
  return blake('ZTxIdOrchardHash', concat([
    compact, memos, noncompact, Buffer.from([o.flags]), o.valueBalance, o.anchor
  ]))
}

function topDigest (tx, transparent) {
  var personalization = Buffer.alloc(16)
  personalization.write('ZcashTxHash_')
  personalization.writeUInt32LE(tx.consensusBranchId >>> 0, 12)
  return blake(personalization, concat([
    headerDigest(tx), transparent, saplingDigest(tx), orchardDigest(tx)
  ]))
}

// Per-transaction cache of the parts of the digest that do not depend on the
// input being signed. Transaction.invalidateHashCache() clears it.
function cached (tx, key, compute) {
  if (!tx.__zip244Cache) tx.__zip244Cache = {}
  if (!tx.__zip244Cache[key]) tx.__zip244Cache[key] = compute()
  return tx.__zip244Cache[key]
}

/** ZIP 244 txid digest, in internal byte order (reverse it to display). */
function txidDigest (tx) {
  return topDigest(tx, transparentTxidDigest(tx))
}

/**
 * ZIP 244 signature digest for transparent input `inIndex`.
 * `prevouts` lists, for EVERY input of the transaction in order, the value and
 * scriptPubKey of the coin it spends: v5 signatures commit to all of them.
 */
function signatureDigest (tx, inIndex, hashType, prevouts) {
  if (VALID_HASH_TYPES.indexOf(hashType) === -1) {
    throw new Error('Invalid hash type for a Zcash v5 transaction: ' + hashType)
  }
  if (!Array.isArray(prevouts) || prevouts.length !== tx.ins.length) {
    throw new Error('Zcash v5 signing needs the value and scriptPubKey of every input (setPrevouts)')
  }

  var anyoneCanPay = (hashType & SIGHASH_ANYONECANPAY) !== 0
  var base = hashType & 0x1f

  var prevoutsSig = anyoneCanPay
    ? blake('ZTxIdPrevoutHash')
    : cached(tx, 'prevouts', function () { return prevoutsDigest(tx.ins) })
  var amountsSig = anyoneCanPay
    ? blake('ZTxTrAmountsHash')
    : cached(tx, 'amounts', function () { return amountsDigest(prevouts) })
  var scriptsSig = anyoneCanPay
    ? blake('ZTxTrScriptsHash')
    : cached(tx, 'scripts', function () { return scriptPubKeysDigest(prevouts) })
  var sequenceSig = anyoneCanPay
    ? blake('ZTxIdSequencHash')
    : cached(tx, 'sequence', function () { return sequenceDigest(tx.ins) })

  var outputsSig
  if (base === SIGHASH_SINGLE) {
    if (inIndex >= tx.outs.length) {
      throw new Error('SIGHASH_SINGLE without a corresponding output')
    }
    outputsSig = outputsDigest([tx.outs[inIndex]])
  } else if (base === SIGHASH_NONE) {
    outputsSig = blake('ZTxIdOutputsHash')
  } else {
    outputsSig = cached(tx, 'outputs', function () { return outputsDigest(tx.outs) })
  }

  var input = tx.ins[inIndex]
  var prevout = prevouts[inIndex]
  var w = new BufferWriter(32 + 4 + varSliceSize(prevout.script) + 8 + 4)
  w.writeSlice(input.hash)
  w.writeUInt32(input.index)
  w.writeUInt64(prevout.value)
  w.writeVarSlice(prevout.script)
  w.writeUInt32(input.sequence)
  var txinSig = blake('Zcash___TxInHash', w.getBuffer())

  var transparent = blake('ZTxIdTranspaHash', concat([
    Buffer.from([hashType]),
    prevoutsSig, amountsSig, scriptsSig, sequenceSig, outputsSig, txinSig
  ]))
  return topDigest(tx, transparent)
}

module.exports = {
  VERSION: VERSION,
  VERSION_GROUP_ID: VERSION_GROUP_ID,
  SIGHASH_ALL: SIGHASH_ALL,
  readBody: readBody,
  byteLength: byteLength,
  writeTx: writeTx,
  cloneInto: cloneInto,
  emptySapling: emptySapling,
  emptyOrchard: emptyOrchard,
  hasShielded: function (tx) { return hasSapling(tx) || hasOrchard(tx) },
  txidDigest: txidDigest,
  signatureDigest: signatureDigest
}
