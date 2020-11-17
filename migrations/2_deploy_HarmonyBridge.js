var HarmonyBridge = artifacts.require("Bridge");

module.exports = function(deployer, network, accounts) {

const threshold = process.env.THRESHOLD;
const maxValidatorCount= process.env.MAX_VALIDATOR_COUNT;
const transferFee = process.env.TRANSFER_FEE;
const coinDailyLimit = process.env.COIN_DAILY_LIMIT;
const chainId = process.env.CHAIN_ID;
const minTransferAmount = process.env.MIN_AMOUNT_TO_TRANSFER;

deployer.then(function() {
  return deployer.deploy(HarmonyBridge, threshold, maxValidatorCount, transferFee, coinDailyLimit, chainId, minTransferAmount).then(function() {
    });
  });
};