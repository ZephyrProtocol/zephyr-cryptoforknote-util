module.exports = require('bindings')('cryptoforknote.node');

const SHA3    = require('sha3');
const bignum  = require('bignum');
const bitcoin = require('bitcoinjs-lib');
const promise = require('promise');
const merklebitcoin = promise.denodeify(require('merkle-bitcoin'));

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

function getMerkleRoot(rpcData, generateTxRaw) {
  hashes = [ reverseBuffer(new Buffer(generateTxRaw, 'hex')).toString('hex') ];
  rpcData.transactions.forEach(function (value) {
    if (value.txid !== undefined) {
      hashes.push(value.txid);
    } else {
      hashes.push(value.hash);
    }
  });
  if (hashes.length === 1) return hashes[0];
  return Object.values(merklebitcoin(hashes))[2].root;
};

function varIntBuffer(n) {
  if (n < 0xfd) {
    return new Buffer([n]);
  } else if (n <= 0xffff) {
    let buff = new Buffer(3);
    buff[0] = 0xfd;
    buff.writeUInt16LE(n, 1);
    return buff;
  } else if (n <= 0xffffffff) {
    let buff = new Buffer(5);
    buff[0] = 0xfe;
    buff.writeUInt32LE(n, 1);
    return buff;
  } else {
    let buff = new Buffer(9);
    buff[0] = 0xff;
    buff.writeUInt64LE(n, 1);
    return buff;
  }
};

module.exports.RavenBlockTemplate = function(rpcData, poolAddress) {
  // epoch length
  const EPOCH_LENGTH = 7500;
  const poolAddrHash = bitcoin.address.fromBase58Check(poolAddress).hash;
  let txCoinbase = new bitcoin.Transaction();
  { // input for coinbase tx
    let blockHeightSerial = rpcData.height.toString(16).length % 2 === 0 ?
                            rpcData.height.toString(16) :
                            '0' + rpcData.height.toString(16);
    const bytesHeight = Math.ceil((rpcData.height << 1).toString(2).length / 8);
    const lengthDiff  = blockHeightSerial.length/2 - bytesHeight;
    for (let i = 0; i < lengthDiff; i++) blockHeightSerial = blockHeightSerial + '00';
    const serializedBlockHeight = new Buffer.concat([
      new Buffer('0' + bytesHeight, 'hex'),
      reverseBuffer(new Buffer(blockHeightSerial, 'hex')),
      new Buffer('00', 'hex') // OP_0
    ]);

    txCoinbase.addInput(
      new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex'),
      0xFFFFFFFF, 0xFFFFFFFF,
      new Buffer.concat([serializedBlockHeight, Buffer('6b6177706f77', 'hex')])
    );

    txCoinbase.addOutput(scriptCompile(poolAddrHash), Math.floor(rpcData.coinbasevalue));

    if (rpcData.default_witness_commitment !== undefined) {
      txCoinbase.addOutput(new Buffer(rpcData.default_witness_commitment, 'hex'), 0);
    }
  }
  const merkleRoot = getMerkleRoot(rpcData, txCoinbase.getHash().toString('hex'));

  let header = new Buffer(80);
  { let position = 0;
    header.writeUInt32BE(rpcData.height, position, 4);                  // height         42-46
    header.write(rpcData.bits, position += 4, 4, 'hex');                // bits           47-50
    header.writeUInt32BE(rpcData.curtime, position += 4, 4, 'hex');     // nTime          51-54
    header.write(merkleRoot, position += 4, 32, 'hex');                 // merkelRoot     55-87
    header.write(rpcData.previousblockhash, position += 32, 32, 'hex'); // prevblockhash  88-120
    header.writeUInt32BE(rpcData.version, position += 32, 4);           // version        121-153
    header = reverseBuffer(header);
  }
  
  let blob = new Buffer.concat([
    header, // 80 bytes
    new Buffer('EEEEEEEEEEEEEEEE', 'hex'), // 8 bytes
    new Buffer('EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE', 'hex'), // 32 bytes
    varIntBuffer(rpcData.transactions.length + 1)
  ]);
  const offset1 = blob.length; 
  blob = new Buffer.concat([ blob, new Buffer(txCoinbase.toHex(), 'hex') ]);

  rpcData.transactions.forEach(function (value) {
    blob = new Buffer.concat([ blob, new Buffer(value.data, 'hex') ]);
  });

  let sha3 = new SHA3.SHA3Hash(256);
  let seedhash_buf = new Buffer(32, 0);
  const epoch_number = Math.floor(rpcData.height / EPOCH_LENGTH);
  for (let i=0; i < epoch_number; i++) {
    seedhash_buf = sha3.update(seedhash_buf).digest();
    sha3.reset();
  }

  const diff1 = 0x00000000ff000000000000000000000000000000000000000000000000000000;
  const difficulty = parseFloat((diff1 / bignum(rpcData.target, 16).toNumber()).toFixed(9));

  return {
    blocktemplate_blob: blob.toString('hex'),
    reserved_offset:    offset1 + 4 /* txCoinbase.version */ + 1 /* txCoinbase.marker */ + 1 /* txCoinbase.flag */ + 1 /* txCoinbase.vinLen */,
    seed_hash:          seedhash_buf.toString('hex'),
    difficulty:         difficulty,
    height:             rpcData.height,
    rpc:                rpcData,
  };
};
