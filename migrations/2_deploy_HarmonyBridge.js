var HarmonyBridge = artifacts.require("Bridge");

module.exports = function(deployer, network, accounts) {

const threshold = 4
const maxValidatorCount = 10
const transferFee = 1
const coinDailyLimit = 500

deployer.then(function() {
  return deployer.deploy(HarmonyBridge, threshold, maxValidatorCount, transferFee, coinDailyLimit).then(function() {
    });
  });
};