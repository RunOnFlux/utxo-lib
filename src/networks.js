// https://en.bitcoin.it/wiki/List_of_address_prefixes
// Dogecoin BIP32 is a proposed standard: https://bitcointalk.org/index.php?topic=409731
var coins = require('./coins')

const bcrypto = require('./crypto')

const hashFunctions = {
  address: bcrypto.hash256, // sha256x2
  transaction: bcrypto.hash256 // sha256x2
}

const groestlHashFunctions = {
  address: bcrypto.groestl,
  transaction: bcrypto.sha256
}

module.exports = {
  bitcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'bc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  testnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'tb',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  litecoin: {
    messagePrefix: '\x19Litecoin Signed Message:\n',
    bech32: 'ltc',
    bip32: {
      public: 0x019da462,
      private: 0x019d9cfe
    },
    pubKeyHash: 0x30,
    scriptHash: 0x32,
    wif: 0xb0,
    coin: coins.LTC,
    hashFunctions: hashFunctions
  },
  dash: {
    messagePrefix: '\x19DarkCoin Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x4c, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x10,
    wif: 0xcc,
    coin: coins.DASH,
    hashFunctions: hashFunctions
  },
  dashTest: {
    messagePrefix: '\x19DarkCoin Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x8c, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x13,
    wif: 0xef, // https://github.com/dashpay/godashutil/blob/master/wif.go#L72
    coin: coins.DASH,
    hashFunctions: hashFunctions
  },
  bitcoincash: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BCH,
    forkId: 0x00,
    hashFunctions: hashFunctions
  },
  bitcoincashTestnet: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
    coin: coins.BCH,
    hashFunctions: hashFunctions
  },
  zcash: {
    messagePrefix: '\x18ZCash Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x4dec4df0
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  zcashTest: {
    messagePrefix: '\x18ZCash Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x1d25,
    scriptHash: 0x1cba,
    wif: 0xef,
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x4dec4df0
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  bitcoingold: {
    messagePrefix: '\x18Bitcoin Gold Signed Message:\n',
    bech32: 'btg',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x26,
    scriptHash: 0x17,
    wif: 0x80,
    coin: coins.BTG,
    forkId: 0x4F, /* 79 */
    hashFunctions: hashFunctions
  },
  komodo: {
    messagePrefix: '\x18Komodo Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x3c,
    scriptHash: 0x55,
    wif: 0xbc,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  safecoin: {
    messagePrefix: '\x18Safecoin Signed Message:\n',
    bip32: {
      public: 0x0488b21f,
      private: 0x0488ade5
    },
    pubKeyHash: 0x3d,
    scriptHash: 0x56,
    wif: 0xbd,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  bithereum: {
    messagePrefix: '\x18Bithereum Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x19,
    scriptHash: 0x28,
    wif: 0x80,
    coin: coins.BTH,
    forkId: 0x55, /* 85 */
    hashFunctions: hashFunctions
  },
  zelcash: {
    messagePrefix: '\x18ZelCash Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  flux: {
    messagePrefix: '\x18ZelCash Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  zero: {
    messagePrefix: '\x18Zero Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x6f76727a,
      4: 0x7361707a
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  snowgem: {
    messagePrefix: '\x18Snowgem Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1c28,
    scriptHash: 0x1c2d,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  gemlink: {
    messagePrefix: '\x18Snowgem Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1c28,
    scriptHash: 0x1c2d,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  commercium: {
    messagePrefix: '\x18Commercium Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1c,
    scriptHash: 0x33,
    wif: 0x8c,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  groestlcoin: {
    messagePrefix: '\x1cGroestlCoin Signed Message:\n',
    bech32: 'grs',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x24,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.GRS,
    hashFunctions: groestlHashFunctions
  },
  zclassic: {
    messagePrefix: '\x18Zclassic Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x930b540d
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  bzedge: {
    messagePrefix: '\x18Bzedge Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x6f77627a,
      4: 0x736c627a
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  genesis: {
    messagePrefix: "\x18Genesis Signed Message: \n",
    bip32: {
      public: 0x53414645,
      private: 0x53616665,
    },
    pubKeyHash: 0x1c,
    scriptHash: 0x3f,
    wif: 0x30,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  bitcoinzero: {
    messagePrefix: "\x18BitcoinZero Signed Message: \n",
    bip32: {
      public:  0x0488b21e,
      private: 0x0488ade4,
    },
    pubKeyHash: 0x4b,
    scriptHash: 0x22,
    wif: 0xd2,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  bitcoinz: {
    messagePrefix: '\x18BitcoinZ Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  hush: {
    messagePrefix: '\x18Hush Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1cb8,
    scriptHash: 0x1cbd,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  ravencoin: {
    messagePrefix: "\x18Ravencoin Signed Message: \n",
    bip32: {
      public:  0x0488b21e,
      private: 0x0488ade4,
    },
    pubKeyHash: 0x3c,
    scriptHash: 0x7a,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  bitcore: {
    messagePrefix: "\x18Bitcore Signed Message: \n",
    bip32: {
      public:  0x0488b21e,
      private: 0x0488ade4,
    },
    pubKeyHash: 0x03,
    scriptHash: 0x7d,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  zcoin: {
    messagePrefix: "\x18Zcoin Signed Message: \n",
    bip32: {
      public:  0x0488b21e,
      private: 0x0488ade4,
    },
    pubKeyHash: 0x52,
    scriptHash: 0x07,
    wif: 0xd2,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  axe: {
    messagePrefix: '\x19Axe Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x37, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x10,
    wif: 0xcc,
    coin: coins.DASH,
    hashFunctions: hashFunctions
  },
  dogecoin: {	
    messagePrefix: '\x19Dogecoin Signed Message:\n',	
    bip32: {	
      public: 0x02facafd,	
      private: 0x02fac398	
    },	
    pubKeyHash: 0x1e, // https://dash-docs.github.io/en/developer-reference#opcodes	
    scriptHash: 0x16,	
    wif: 0x9e,	
    coin: coins.BTC,	
    hashFunctions: hashFunctions	
  },	
  digibyte: {	
    messagePrefix: '\x19Digibyte Signed Message:\n',
    bech32: 'dgb',
    bip32: {	
      public: 0x0488b21e,	
      private: 0x0488ade4	
    },	
    pubKeyHash: 0x1e, // https://dash-docs.github.io/en/developer-reference#opcodes	
    scriptHash: 0x3f,	
    wif: 0x80,	
    coin: coins.BTC,	
    hashFunctions: hashFunctions	
  },	
  sinovate: {	
    messagePrefix: '\x18Sinovate Signed Message:\n',	
    bip32: {	
      public: 0x0488b21e,	
      private: 0x0488ade4	
    },	
    pubKeyHash: 0x3f, // https://dash-docs.github.io/en/developer-reference#opcodes	
    scriptHash: 0x05,	
    wif: 0xbf,	
    coin: coins.BTC,	
    hashFunctions: hashFunctions	
  },
  ilcoin: {
    messagePrefix: '\x18ILCoin Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x00,
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  raptoreum: {
    messagePrefix: '\x19DarkCoin Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x3c, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x10,
    wif: 0x80,
    coin: coins.DASH,
    hashFunctions: hashFunctions
  },
  vertcoin: {
    messagePrefix: '\x18Bitcoin Signed Message:\n',
    bech32: 'vtc',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x47, // https://dash-docs.github.io/en/developer-reference#opcodes
    scriptHash: 0x05,
    wif: 0x80,
    coin: coins.BTC,
    hashFunctions: hashFunctions
  },
  fluxtestnet: {
    messagePrefix: '\x18ZelCash Signed Message:\n',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394
    },
    pubKeyHash: 0x1d25,
    scriptHash: 0x1cba,
    wif: 0xef,
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  fluxidentity: {
    messagePrefix: '\x18ZelCash Signed Message:\n',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1d25, // testnet value
    scriptHash: 0x1cba, // testnet value
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  },
  /* btcp: { // TODO
    messagePrefix: '\x18Bitcoin Private Signed Message:\n',
    bech32: 'btg',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x1325,
    scriptHash: 0x13af,
    wif: 0x80,
    coin: coins.BTG,
    forkId: 0x2a,
    hashFunctions: hashFunctions
  },
  anon: { // TODO
    messagePrefix: '\x18Anon Signed Message:\n',
    bech32: 'btg',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x0582,
    scriptHash: 0x5389,
    wif: 0x80,
    coin: coins.BTG,
    forkId: 0x2a,
    hashFunctions: hashFunctions
  },
  zen: { // TODO
    messagePrefix: '\x18Horizen Signed Message:\n',
    bech32: 'zen',
    bip32: {
      public: 0x0488b21e,
      private: 0x0488ade4
    },
    pubKeyHash: 0x2089,
    scriptHash: 0x2096,
    wif: 0x80,
    // This parameter was introduced in version 3 to allow soft forks, for version 1 and 2 transactions we add a
    // dummy value.
    consensusBranchId: {
      1: 0x00,
      2: 0x00,
      3: 0x5ba81b19,
      4: 0x76b809bb
    },
    coin: coins.ZEC,
    hashFunctions: hashFunctions
  }, */
}