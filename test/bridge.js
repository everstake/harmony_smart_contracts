// const { count, assert } = require('console');
const keccak256 = require("keccak256");
const ethSig = require("nano-ethereum-signer");
const assert = require("assert");

const HarmonyBridge = artifacts.require("Bridge");
const EdgewareToken = artifacts.require("EdgewareToken");

const currentTime = (Date.now() / 1000).toFixed();

contract("Bridge", async (accounts) => {
  contract("Change Bridge parameters", async (accounts) => {
    let bridgeContract, edgewareToken;

    before(async () => {
      bridgeContract = await HarmonyBridge.deployed();
      edgewareToken = await EdgewareToken.deployed();
    });

    it("Not an admin try to change fee", async () => {
      const fee = 1;
      try {
        await bridgeContract.setFee(fee, { from: accounts[1] });
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Admin to change fee successfully", async () => {
      const expectedFee = 55;
      await bridgeContract.setFee(expectedFee, { from: accounts[0] });
      const actualFee = await bridgeContract.fee.call();
      assert.strictEqual(
        expectedFee,
        Number(actualFee),
        `fees ${expectedFee} is not equal ${actualFee}`
      );
    });

    it("Not an admin try to add Validator", async () => {
      try {
        await bridgeContract.addValidator(
          "0xA56c96CaA3d912945b972cB750f885496815C084",
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Ovner added a new validator successfully", async () => {
      const expectedValidator = "0xA56c96CaA3d912945b972cB750f885496815C084";
      const expextedCountValidators = 1;
      const { logs } = await bridgeContract.addValidator(expectedValidator, {
        from: accounts[0],
      });
      assert.strictEqual(logs[0].args.validator, expectedValidator);
      assert.strictEqual(
        Number(logs[0].args.totalActiveValidators),
        expextedCountValidators
      );
      assert.strictEqual(logs[0].args.isActive, true);
    });

    it("Not an admin try to remove Validator", async () => {
      try {
        await bridgeContract.removeValidator(
          "0xA56c96CaA3d912945b972cB750f885496815C084",
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to add Worker", async () => {
      try {
        await bridgeContract.addWorker(
          "0xA56c96CaA3d912945b972cB750f885496815C084",
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to remove Worker", async () => {
      try {
        await bridgeContract.removeWorker(
          "0xA56c96CaA3d912945b972cB750f885496815C084",
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to set threshold", async () => {
      try {
        await bridgeContract.setThreshold(5, { from: accounts[1] });
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to add token", async () => {
      try {
        await bridgeContract.addToken(
          edgewareToken.address,
          8,
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to remove token", async () => {
      try {
        await bridgeContract.removeToken(
          edgewareToken.address,
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to set daily limit", async () => {
      try {
        await bridgeContract.setDailyLimit(
          5,
          edgewareToken.address,
          { from: accounts[1] }
        );
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });

    it("Not an admin try to set expiration time", async () => {
      try {
        await bridgeContract.setNewDurationBeforeExpirationTime(5, { from: accounts[1] });
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Ownable: caller is not the owner"),
          error.toString()
        );
      }
    });
  });

  contract("Submit signatures", async (accounts) => {
    let bridgeContract;
    let edgewareToken;
    before(async () => {
      bridgeContract = await HarmonyBridge.deployed();
      edgewareToken = await EdgewareToken.deployed();

      let keys = Object.keys(validators);
      for (let i = 0; i < keys.length; i++) {
        await bridgeContract.addValidator(keys[i], { from: accounts[0] });
      }
      await bridgeContract.addWorker(accounts[1], { from: accounts[0] });
      await bridgeContract.addToken(
        edgewareToken.address,
        10,
        { from: accounts[0] }
      );
    });

    it("Send swap request", async () => {
      const startBalance = 5;
      let message = getSwapMessage(accounts[3]);
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });

      let balanceBefore = await web3.eth.getBalance(bridgeContract.address);
      assert.strictEqual(parseInt(balanceBefore), startBalance);
      let signatures = signSwapMessage(hashMessage(message), 4);

      await bridgeContract.setFee(1, { from: accounts[0] });
      await bridgeContract.requestSwap(message, signatures, {
        from: accounts[1],
      });
      const expectedBalance = startBalance - message.amount;
      let balanceAfterTest = await web3.eth.getBalance(bridgeContract.address);
      assert.strictEqual(parseInt(balanceAfterTest), expectedBalance);
    });

    it("Send token swap", async () => {
      const startBalance = 5;
      let message = getSwapMessage(accounts[2]);
      message.asset = edgewareToken.address;
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      let signatures = signSwapMessage(hashMessage(message), 4);
      await edgewareToken.setBridgeAddress(bridgeContract.address, {from: accounts[0]});
      const {receipt} = await bridgeContract.requestSwap(message, signatures, {
        from: accounts[1],
        gasValue: 200000,
      });
      assert.strictEqual(Number(receipt.rawLogs[0].data) , message.amount);
    });

    it("Send swap request with wrong count of signatures", async () => {
      const startBalance = 5;
      let message = getSwapMessage(accounts[2]);
      let signatures = signSwapMessage(hashMessage(message), 3);
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      try {
        await bridgeContract.requestSwap(message, signatures, {
          from: accounts[1],
        });
        assert.fail();
      } catch (error) {
        assert(
          error
            .toString()
            .includes("Wrong count of signatures to make transfer"),
          error.toString()
        );
      }
    });

    it("Send swap request with one signature not from Validator", async () => {
      const startBalance = 5;
      let message = getSwapMessage(accounts[2]);
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      let signatures = signSwapMessage(hashMessage(message), 5);
      signatures.splice(0, 1);
      try {
        await bridgeContract.requestSwap(message, signatures, {
          from: accounts[1],
        });
      } catch (error) {
        assert(
          error.toString().includes("Signatures verification is failed"),
          error.toString()
        );
      }
    });

    it("Send swap request with one signature of wrong data", async () => {
      const startBalance = 5;
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      let message = getSwapMessage(accounts[2]);
      let signatures = signSwapMessage(hashMessage(message), 4);
      message.amount = 1;
      let wrong_signature = signSwapMessage(hashMessage(message), 1);
      signatures.splice(0, 1);
      signatures.push(wrong_signature[0]);
      try {
        await bridgeContract.requestSwap(message, signatures, {
          from: accounts[1],
        });
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Signatures verification is failed"),
          error.toString()
        );
      }
    });

    it("Send swap request signed only one Validator", async () => {
      const startBalance = 5;
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      let message = getSwapMessage(accounts[2]);
      let signatures = [];
      for (let i = 0; i < 4; i++) {
        let s = signSwapMessage(hashMessage(message), 1);
        signatures.push(s[0]);
      }
      try {
        await bridgeContract.requestSwap(message, signatures, {
          from: accounts[1],
        });
        assert.fail();
      } catch (error) {
        assert(
          error.toString().includes("Signatures verification is failed"),
          error.toString()
        );
      }
    });

    it("Send token swap and reached daily limit", async () => {
      const startBalance = 20;
      await bridgeContract.send(startBalance * 1 ** 18, { from: accounts[2] });
      let message = getSwapMessage(accounts[2]);

      message.asset = edgewareToken.address;
      message.amount = 8;
      await edgewareToken.setBridgeAddress(bridgeContract.address, {from: accounts[0]});
      let signatures = signSwapMessage(hashMessage(message), 4);
      try {
      await bridgeContract.requestSwap(message, signatures, {
        from: accounts[1],
      });
      assert.fail();
    } catch (error) {
      assert(
        error.toString().includes("Daily limit has already reached for this asset"),
        error.toString()
      );
    }
  });
});

  contract("Submit signatures with time travel", async (accounts) => {
    it("Send token swap and check updating daily limit", async () => {
      let ctrObj = await HarmonyBridge.deployed();
      let edgewareToken = await EdgewareToken.deployed();
      const startBalance = 20;
      await ctrObj.send(startBalance * 1 ** 18, { from: accounts[2] });
      let keys = Object.keys(validators);
      for (let i = 0; i < keys.length - 1; i++) {
        await ctrObj.addValidator(keys[i]);
      }
      await ctrObj.addWorker(accounts[1]);
      await ctrObj.addToken(edgewareToken.address, 10, {from: accounts[0]});
      await edgewareToken.setBridgeAddress(ctrObj.address, {from: accounts[0]});
     //  await ctrObj.setNewDurationBeforeExpirationTime((Date.now() / 1000).toFixed());

      let message = getSwapMessage(accounts[2]);
      message.asset = edgewareToken.address;
      message.amount = 1;
      let signatures = signSwapMessage(hashMessage(message), 4);
      const  {receipt} = await ctrObj.requestSwap(message, signatures, {
        from: accounts[1],
      });
      assert.strictEqual(Number(receipt.rawLogs[0].data) , message.amount);
      await advanceTime(86401);
      message.amount = 1;
      message.timestamp = (Date.now() / 1000).toFixed();
      await ctrObj.addToken(edgewareToken.address, 10, {from: accounts[0]});
      signatures = signSwapMessage(hashMessage(message), 4);
      const res = await ctrObj.requestSwap(message, signatures, {
        from: accounts[1],
      });
      let secondSpent = await ctrObj.dailySpend(
        edgewareToken.address
      );
      assert.strictEqual(Number(res.receipt.rawLogs[0].data) , message.amount);
      assert.strictEqual(secondSpent.toString(), "2");
    });

    it("Send token swap with expiration time", async () => {
      let ctrObj = await HarmonyBridge.deployed();
      let edgewareToken = await EdgewareToken.deployed();
      let keys = Object.keys(validators);
      for (let i = 0; i < keys.length - 1; i++) {
        await ctrObj.addValidator(keys[i]);
      }
      await ctrObj.addWorker(accounts[1]);
      await ctrObj.addToken(edgewareToken.address, 10);
      await edgewareToken.setBridgeAddress(ctrObj.address, {from: accounts[0]});
      let message = getSwapMessage(accounts[2]);
      message.asset = edgewareToken.address;
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
    chainId: 27,
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
