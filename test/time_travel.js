const keccak256 = require("keccak256");
const ethSig = require("nano-ethereum-signer");
const assert = require("assert");

const HarmonyBridge = artifacts.require("Bridge");
const EdgewareToken = artifacts.require("EdgewareToken");

const currentTime = (Date.now()/1000).toFixed();

contract("HarmonyBridge", async (accounts) => {


  contract("Submit signatures with time travel", async (accounts) => {
    let edgewareToken, ctrObj;
    before(async () => {
      ctrObj = await HarmonyBridge.deployed();
      edgewareToken = await EdgewareToken.deployed();
      const startBalance = 20;
      await ctrObj.send(startBalance * 1 ** 18, { from: accounts[2] });
      let keys = Object.keys(validators);
      for (let i = 0; i < keys.length - 1; i++) {
        await ctrObj.addValidator(keys[i]);
      }
      await ctrObj.setNewDurationBeforeExpirationTime(100000);
      await ctrObj.addWorker(accounts[1]);
      await ctrObj.addToken(edgewareToken.address, 100000000000, {from: accounts[0]});
      await edgewareToken.setBridgeAddress(ctrObj.address, {from: accounts[0]});
    });
    it("Send token swap and check updating daily limit", async () => {
      await edgewareToken.mintFor(accounts[1], 10000, { from: accounts[0] });

      await ctrObj.transferToken('receiver', 100, edgewareToken.address, {from: accounts[1]});

      await advanceTime(86401);

      await ctrObj.transferToken('receiver', 50, edgewareToken.address, {from: accounts[1]});
      
      let secondSpent = await ctrObj.dailySpend(
        edgewareToken.address
      );

      assert.strictEqual(secondSpent.toString(), "50");
    });

    it("Send token swap with expiration time", async () => {

      let message = getSwapMessage(accounts[2]);
      let signatures = signSwapMessage(hashMessage(message), 4);
      await advanceTime(86402);
      try {
        await ctrObj.requestSwap(message, signatures, {
          from: accounts[1],
        });
      } catch (error) {
        assert(
          error.toString().includes("Transaction can't be sent because of expiration time"),
          error.toString()
        );
      }
    });
  });
});

const validators = {
  "0x165dcF0135AB52738d1737833353bbA419E1c63b":
    "01f903ce0c960ff3a9e68e80ff5ffc344358d80ce1c221c3f9711af07f83a3bd",
  "0xA56c96CaA3d912945b972cB750f885496815C084":
    "1c9c31dc66ee13cf14fe6dbcc036cdcb4e05326b17ea38ef86bbd2463340144d",
  "0x47cEE989d67bCb4898CE7cAFd050efFb2F45Cc02":
    "e8cae5c825f7b167af4b6731eae7aabc7b00851de6d3c561175f9e6c36bfe9a7",
  "0x1Fcef4CDEa62a9B91Df4C7B7b747CD702997Ec9B":
    "8eb5f8e9eb261fdc151f51f34466334a16e67f0254cfaaa1a5b64677a74a449f",
  "0xf2bbeCce16Cb246Ba91044AC2aDE5999E53fE403":
    "e9115ead614ecdd29d8612390691a018e701ff83820ace53cef1f228c6b8261c",
};

function getSwapMessage(receiverAccount) {
  let swapMessage = {
    chainId: process.env.CHAIN_ID,
    receiver: receiverAccount,
    sender: "0xC1A9A401B40eA5D90227570c71e9472102E16806",
    timestamp: currentTime,
    amount: 3,
    asset: "0x0000000000000000000000000000000000000000",
    transferNonce: 1,
  };
  return swapMessage;
}

function hashMessage(message) {
  let abiMessage = web3.eth.abi.encodeParameters(
    ["uint", "address", "string", "uint", "uint", "address", "uint"],
    [
      message.chainId,
      message.receiver,
      message.sender,
      message.timestamp,
      message.amount,
      message.asset,
      message.transferNonce,
    ]
  );
  return "0x" + keccak256(abiMessage).toString("hex");
}

function signSwapMessage(message, countOfSignatures) {
  // console.log(`Signed message: ${message}`);
  let signatures = [];
  let keys = Object.keys(validators);
  for (let i = 0; i < countOfSignatures; i++) {
    const sigObj = ethSig.signMessage(message, validators[keys[i]]);
    signatures.push(sigObj);
  }
  return signatures;
}

advanceTime = (time) => {
  return new Promise((resolve, reject) => {
    web3.currentProvider.send(
      {
        jsonrpc: "2.0",
        method: "evm_increaseTime",
        params: [time],
        id: new Date().getTime(),
      },
      (err, result) => {
        if (err) {
          return reject(err);
        }
        return resolve(result);
      }
    );
  });
};

function sleepAsync(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}