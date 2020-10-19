// const { count, assert } = require('console');
const keccak256 = require('keccak256');
const ethSig = require('nano-ethereum-signer');
const assert = require('assert');

const HarmonyBridge = artifacts.require("Bridge");

const currentTime = (Date.now() / 1000).toFixed();

contract("Bridge", async accounts => {
    contract("Change Bridge parameters", async accounts => {
        let meta;

        before(async () => {
            let ctrObj = await HarmonyBridge.deployed();
            meta = ctrObj;
          });

        it("Not an admin try to change fee", async () => {
            try {
                await meta.setFee(777, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to add Validator", async () => {
            try {
                await meta.addValidator("0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to remove Validator", async () => {
            try {
                await meta.removeValidator("0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to add Worker", async () => {
            try {
                await meta.addWorker("0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to remove Worker", async () => {
            try {
                await meta.removeWorker("0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to set threshold", async () => {
            try {
                await meta.setThreshold(5, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to add token", async () => {
            try {
                await meta.addToken("0xA56c96CaA3d912945b972cB750f885496815C084", 8, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to remove token", async () => {
            try {
                await meta.removeToken("0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to set daily limit", async () => {
            try {
                await meta.setDailyLimit(5, "0xA56c96CaA3d912945b972cB750f885496815C084", {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });

        it("Not an admin try to set expiration time", async () => {
            try {
                await meta.setTxExpirationTime(5, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Only owner can call this function")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because only owner can configure Bridge SC parameters");
        });
    });

    contract("Submit signatures", async accounts => {
        let meta;

        before(async () => {
            let ctrObj = await HarmonyBridge.deployed();
            meta = ctrObj;
            let keys = Object.keys(validators);
            for (let i = 0; i < keys.length - 1; i++) {
                await meta.addValidator(keys[i]);
            }
            await meta.addWorker(accounts[1]);
            await meta.addToken("0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf", 10);
          });

        it("Send swap request", async () => {
            let message = getSwapMessage();
            let signatures = signSwapMessage(hashMessage(message), 4);

            let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            if (swapRes) {
                return;
            } else {
                throw("Request on swap transaction was failed");
            }
        });

        it("Send token swap", async () => {
            let message = getSwapMessage();
            message.asset = "0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf";
            let signatures = signSwapMessage(hashMessage(message), 4);
            let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            if (swapRes) {
                return;
            } else {
                throw("Request on token swap transaction was failed");
            }
        });

        it("Send swap request with wrong count of signatures", async () => {
            let message = getSwapMessage();
            let signatures = signSwapMessage(hashMessage(message), 3);
            try {
                let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Wrong count of signatures to make transfer")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because of wrong number of signatures");
        });

        it("Send swap request with one signature not from Validator", async () => {
            let message = getSwapMessage();
            let signatures = signSwapMessage(hashMessage(message), 5);
            signatures.splice(0, 1);
            try {
                let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Signatures verification is failed")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because of one signature not from Validator");
        });

        it("Send swap request with one signature of wrong data", async () => {
            let message = getSwapMessage();
            let signatures = signSwapMessage(hashMessage(message), 4);
            message.amount = 1;
            let wrong_signature = signSwapMessage(hashMessage(message), 1);
            signatures.splice(0,1);
            signatures.push(wrong_signature[0]);
            try {
                let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Signatures verification is failed")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because of one wrong wignature");
        });

        it("Send swap request signed only one Validator", async () => {
            let message = getSwapMessage();
            let signatures = [];
            for (let i = 0; i < 4; i++) {
                let s = signSwapMessage(hashMessage(message), 1);
                signatures.push(s[0]);
            }
            try {
                let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Signatures verification is failed")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because one Validator sends neccessary signature threshold");
        });
        
        it("Send token swap and reached daily limit", async () => {
            let message = getSwapMessage();
            message.asset = "0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf";
            message.amount = 8;
            let signatures = signSwapMessage(hashMessage(message), 4);
            try {
                let swapRes = await meta.requestSwap(message, signatures, {'from': accounts[1]});
            } catch (e) {
                if (JSON.stringify(e).includes("Daily limit has already reached for this asset")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because daily asset transfer limit was reached");
        });
    })

    contract("Submit signatures with time travel", async accounts => {
        it("Send token swap and check updating daily limit", async () => {
            let ctrObj = await HarmonyBridge.deployed();
            let keys = Object.keys(validators);
            for (let i = 0; i < keys.length - 1; i++) {
                await ctrObj.addValidator(keys[i]);
            }
            await ctrObj.addWorker(accounts[1]);
            await ctrObj.addToken("0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf", 10);
            await ctrObj.setTxExpirationTime(100000);

            let message = getSwapMessage();
            message.asset = "0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf";
            message.amount = 1;
            let signatures = signSwapMessage(hashMessage(message), 4);
            let swapRes = await ctrObj.requestSwap(message, signatures, {'from': accounts[1]});
            await advanceTime(86401);
            message.amount = 1;
            message.timestamp = (Date.now() / 1000).toFixed();
            signatures = signSwapMessage(hashMessage(message), 4);
            swapRes = await ctrObj.requestSwap(message, signatures, {'from': accounts[1]});
            let secondSpent = await ctrObj.dailySpend("0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf");
            assert.strictEqual(secondSpent.toString(), '1');
        });

        it("Send token swap with expiration time", async () => {
            let ctrObj = await HarmonyBridge.deployed();
            let keys = Object.keys(validators);
            for (let i = 0; i < keys.length - 1; i++) {
                await ctrObj.addValidator(keys[i]);
            }
            await ctrObj.addWorker(accounts[1]);
            await ctrObj.addToken("0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf", 10);

            let message = getSwapMessage();
            message.asset = "0xa5C00BCfa2b37660Db0A0d88B9dB2cB174d6d8cf";
            let signatures = signSwapMessage(hashMessage(message), 4);
            await advanceTime(86402);
            try {
                let swapRes = await ctrObj.requestSwap(message, signatures, {'from': accounts[1]});
            } catch(e) {
                if (JSON.stringify(e).includes("Transaction can't be sent because of expiration time")) {
                    return;
                } else {
                    throw(e);
                }
            }
            throw("Method call should fail because of transaction expiration time");
        });
    })
})

const validators = {
    '0x165dcF0135AB52738d1737833353bbA419E1c63b': '01f903ce0c960ff3a9e68e80ff5ffc344358d80ce1c221c3f9711af07f83a3bd',
    '0xA56c96CaA3d912945b972cB750f885496815C084': '1c9c31dc66ee13cf14fe6dbcc036cdcb4e05326b17ea38ef86bbd2463340144d',
    '0x47cEE989d67bCb4898CE7cAFd050efFb2F45Cc02': 'e8cae5c825f7b167af4b6731eae7aabc7b00851de6d3c561175f9e6c36bfe9a7',
    '0x1Fcef4CDEa62a9B91Df4C7B7b747CD702997Ec9B': '8eb5f8e9eb261fdc151f51f34466334a16e67f0254cfaaa1a5b64677a74a449f',
    '0xf2bbeCce16Cb246Ba91044AC2aDE5999E53fE403': 'e9115ead614ecdd29d8612390691a018e701ff83820ace53cef1f228c6b8261c'
}

function getSwapMessage() {
    let swapMessage = {
        chainId: 27,
        receiver: "0xC1A9A401B40eA5D90227570c71e9472102E16806",
        sender: "0xC1A9A401B40eA5D90227570c71e9472102E16806",
        timestamp: currentTime,
        amount: 3,
        asset: "0x0000000000000000000000000000000000000000",
        transferNonce: 1
      };
    return swapMessage;
}

function hashMessage(message) {
    let abiMessage = web3.eth.abi.encodeParameters(['uint', 'address', 'string', 'uint', 'uint', 'address', 'uint'],
                                                    [message.chainId, message.receiver, message.sender, message.timestamp, message.amount, message.asset, message.transferNonce]);
    return '0x'+keccak256(abiMessage).toString('hex')
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
        web3.currentProvider.send({
            jsonrpc: "2.0",
            method: "evm_increaseTime",
            params: [time],
            id: new Date().getTime()
        }, (err, result) => {
            if (err) { return reject(err); }
            return resolve(result);
        });
    });
}
