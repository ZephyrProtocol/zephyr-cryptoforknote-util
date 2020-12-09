module.exports = require('bindings')('cryptoforknote.node');

const SHA3    = require('sha3');
const bignum  = require('bignum');
const bitcoin = require('bitcoinjs-lib');
const varuint = require('varuint-bitcoin');
const crypto  = require('crypto');
const fastMerkleRoot = require('merkle-lib/fastRoot');

function scriptCompile(addrHash) {
  return bitcoin.script.compile([
    bitcoin.opcodes.OP_DUP,
    bitcoin.opcodes.OP_HASH160,
    addrHash,
    bitcoin.opcodes.OP_EQUALVERIFY,
    bitcoin.opcodes.OP_CHECKSIG
  ]);
}

function reverseBuffer(buff) {
  let reversed = new Buffer(buff.length);
  for (var i = buff.length - 1; i >= 0; i--) reversed[buff.length - i - 1] = buff[i];
  return reversed;
}

function txesHaveWitnessCommit(transactions) {
  return (
    transactions instanceof Array &&
    transactions[0] &&
    transactions[0].ins &&
    transactions[0].ins instanceof Array &&
    transactions[0].ins[0] &&
    transactions[0].ins[0].witness &&
    transactions[0].ins[0].witness instanceof Array &&
    transactions[0].ins[0].witness.length > 0
  );
}

function sha256(buffer) {
  return crypto.createHash('sha256').update(buffer).digest();
};

function hash256(buffer) {
  return sha256(sha256(buffer));
};

function getMerkleRoot(transactions) {
  if (transactions.length === 0) return new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
  const forWitness = txesHaveWitnessCommit(transactions);
  const hashes = transactions.map(transaction => transaction.getHash(forWitness));
  const rootHash = fastMerkleRoot(hashes, hash256);
  console.log(forWitness);
  return forWitness ? hash256(Buffer.concat([rootHash, transactions[0].ins[0].witness[0]])) : rootHash;
}

let last_epoch_number;
let last_seed_hash;
const diff1 = 0x00000000ff000000000000000000000000000000000000000000000000000000;

module.exports.RavenBlockTemplate = function(rpcData, poolAddress) {
  const poolAddrHash = bitcoin.address.fromBase58Check(poolAddress).hash;

  let txCoinbase = new bitcoin.Transaction();
  let bytesHeight;
  { // input for coinbase tx
    let blockHeightSerial = rpcData.height.toString(16).length % 2 === 0 ?
                                  rpcData.height.toString(16) :
                            '0' + rpcData.height.toString(16);
    bytesHeight = Math.ceil((rpcData.height << 1).toString(2).length / 8);
    const lengthDiff  = blockHeightSerial.length/2 - bytesHeight;
    for (let i = 0; i < lengthDiff; i++) blockHeightSerial = blockHeightSerial + '00';
    const serializedBlockHeight = new Buffer.concat([
      new Buffer('0' + bytesHeight, 'hex'),
      reverseBuffer(new Buffer(blockHeightSerial, 'hex')),
      new Buffer('00', 'hex') // OP_0
    ]);

    txCoinbase.addInput(
      // will be used for our reserved_offset extra_nonce
      new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      0xFFFFFFFF, 0xFFFFFFFF,
      new Buffer.concat([serializedBlockHeight, Buffer('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', 'hex')]) // 17 bytes
    );

    txCoinbase.addOutput(scriptCompile(poolAddrHash), Math.floor(rpcData.coinbasevalue));

    if (rpcData.default_witness_commitment) {
      txCoinbase.addOutput(new Buffer(rpcData.default_witness_commitment, 'hex'), 0);
    }
  }

  let header = new Buffer(80);
  { let position = 0;
    header.writeUInt32BE(rpcData.height, position, 4);                  // height         42-46
    header.write(rpcData.bits, position += 4, 4, 'hex');                // bits           47-50
    header.writeUInt32BE(rpcData.curtime, position += 4, 4, 'hex');     // nTime          51-54
    header.write('DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD', position += 4, 32, 'hex');                 // merkelRoot     55-87
    header.write(rpcData.previousblockhash, position += 32, 32, 'hex'); // prevblockhash  88-120
    header.writeUInt32BE(rpcData.version, position += 32, 4);           // version        121-153
    header = reverseBuffer(header);
  }
  
  let blob = new Buffer.concat([
    header, // 80 bytes
    new Buffer('AAAAAAAAAAAAAAAA', 'hex'), // 8 bytes
    new Buffer('BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', 'hex'), // 32 bytes
    varuint.encode(rpcData.transactions.length + 1, new Buffer(varuint.encodingLength(rpcData.transactions.length + 1)), 0)
  ]);
  const offset1 = blob.length; 
  blob = new Buffer.concat([ blob, new Buffer(txCoinbase.toHex(), 'hex') ]);

  rpcData.transactions.forEach(function (value) {
    blob = new Buffer.concat([ blob, new Buffer(value.data, 'hex') ]);
  });

  const EPOCH_LENGTH = 7500;
  const epoch_number = Math.floor(rpcData.height / EPOCH_LENGTH);
  if (last_epoch_number !== epoch_number) {
    let sha3 = new SHA3.SHA3Hash(256);
    if (last_epoch_number && last_epoch_number + 1 === epoch_number) {
      last_seed_hash = sha3.update(last_seed_hash).digest();
    } else {
      last_seed_hash = new Buffer(32, 0);
      for (let i = 0; i < epoch_number; i++) {
        last_seed_hash = sha3.update(last_seed_hash).digest();
        sha3.reset();
      }
    }
    last_epoch_number = epoch_number;
  }

  const difficulty = parseFloat((diff1 / bignum(rpcData.target, 16).toNumber()).toFixed(9));

  return {
    blocktemplate_blob: blob.toString('hex'),
    // reserved_offset to CCCCCC....
    reserved_offset:    offset1 + 4 /* txCoinbase.version */ + 1 /* vinLen */  + 32 /* hash */ + 4 /* index  */ +
                        1 /* vScript len */ + 1 /* coinbase height len */ + bytesHeight + 1 /* trailing zero byte */,
    seed_hash:          last_seed_hash.toString('hex'),
    difficulty:         difficulty,
    height:             rpcData.height,
    bits:               rpcData.bits,
  };
};

function update_merkle_root_hash(blob_in, blob_out) {
  let offset = 80 + 8 + 32;
  const nTransactions = varuint.decode(blob_in, offset);
  offset += varuint.decode.bytes;
  let transactions = [];
  for (let i = 0; i < nTransactions; ++i) {
    const tx = bitcoin.Transaction.fromBuffer(blob_in.slice(offset), true);
    transactions.push(tx);
    offset += tx.byteLength();
  }
  getMerkleRoot(transactions).copy(blob_out, 4 + 32);
};

module.exports.convertRavenBlob = function(blobBuffer) {
  let header = blobBuffer.slice(0, 80);
  update_merkle_root_hash(blobBuffer, header);
  return reverseBuffer(hash256(header));
};

module.exports.constructNewRavenBlob = function(blockTemplate, nonceBuff, mixhashBuff) {
  update_merkle_root_hash(blockTemplate, blockTemplate);
  nonceBuff.copy  (blockTemplate, 80, 0, 8);
  mixhashBuff.copy(blockTemplate, 88, 0, 32);
  return blockTemplate;
};

module.exports.constructNewDeroBlob = function(blockTemplate, nonceBuff) {
  nonceBuff.copy(blockTemplate, 39, 0, 4);
  return blockTemplate;
};