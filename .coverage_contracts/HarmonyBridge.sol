// SPDX-License-Identifier: MIT
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/cryptography/ECDSA.sol";
import "./EdgewareToken.sol";

contract Bridge is Ownable {
function c_0xb095bd59(bytes32 c__0xb095bd59) public pure {}

    using SafeMath for uint256;

    mapping(address => bool) public tokens;
    mapping(address => bool) public validators;
    mapping(address => bool) public workers;
    mapping(address => uint256) public dailyLimit;
    mapping(address => uint256) public dailySpend;
    uint256 public fee;

    mapping(address => uint256) dailyLimitSetTime;
    uint256 signatureThreshold;
    uint256 public maxValidatorsCount;
    uint256 public currentValidatorsCount;
    uint256 durationBeforeExpirationTime;
    uint256 transferNonce;

    event TokensTransfered(
        string indexed receiver,
        address indexed sender,
        uint256 amount,
        address asset,
        uint256 transferNonce,
        uint256 timestamp
    );

    event ValidatorsCountChanged(
        address validator,
        bool isActive,
        uint256 totalActiveValidators
    );

    struct SwapMessage {
        uint256 chainId;
        address payable receiver;
        string sender;
        uint256 timestamp;
        uint256 amount;
        address asset;
        uint256 transferNonce;
    }

    modifier onlyWorker() {c_0xb095bd59(0xf0f675677a32d5a6f1b96b18b3a60f74efa1a4a17e2316806af4feebf22af55c); /* function */ 

c_0xb095bd59(0x0b1a3fed9bbc201e37026f7958f4b51f54e51b2044452ad6cc600a55e0a51adb); /* line */ 
        c_0xb095bd59(0xac277516bc0cb473fb73b6d5bfa145c31d7fd3822451ac2f9a7f60686c652ffb); /* assertPre */ 
c_0xb095bd59(0xc054f5fee75cba539b9d2c463e23db7c32d119dcba379e5204f4746909ac0d42); /* statement */ 
require(workers[msg.sender], "Only worker can call this function.");c_0xb095bd59(0xd6f4c57a9f6307a3281b6465e6a2bf2f9ce40fca766ce06cd43d0d41ac20da04); /* assertPost */ 

c_0xb095bd59(0x6e08891ec3076a08d6bd3fe0b7c455364d15750f1015405f56b2d10f5e61c15c); /* line */ 
        _;
    }

    constructor(
        uint256 threshold,
        uint256 maxPermissibleValidatorCount,
        uint256 transferFee,
        uint256 coinDailyLimit
    ) public Ownable() {c_0xb095bd59(0x9e65633b22c4bedebc5e1f38696d51af45b43b6252e7639dc2f54d65af2c14d0); /* function */ 

c_0xb095bd59(0xb358e9162358af11939fa8e09fc03ad66ee2ee84c9e8625accd73f56ab6bda90); /* line */ 
        c_0xb095bd59(0x70283534a9507dc96fa69f208d8675bbbff9546d3ae00ef3cae0a1e52934dc73); /* statement */ 
signatureThreshold = threshold;
c_0xb095bd59(0x8927bad58db7c107fde9c935eefb840e30e4f0f7a5ad91e5b7d9142ae3a7f984); /* line */ 
        c_0xb095bd59(0xae7117a48105df3fa5f8f90096c4d9442e73bbd2dc29a397d6724eea04d966a8); /* statement */ 
maxValidatorsCount = maxPermissibleValidatorCount;
c_0xb095bd59(0x22a5babb55e6fd7a81b4ceb1fa1b099e3fcfbd6ed74a9ea595b5894d92b698e8); /* line */ 
        c_0xb095bd59(0x986d3fa996861c43a41bf2f7f827417bc7537107751bcc17f3b5b90a640767d4); /* statement */ 
currentValidatorsCount = 0;
c_0xb095bd59(0x133a6ee380c2f100dbca7f337440a0e2a0d252e8e1dac3c3f0a39067b9a93e03); /* line */ 
        c_0xb095bd59(0x8507633fff02a505a650221ba86430fa4449ec1cb6d662b45ea4bb539c1f311a); /* statement */ 
fee = transferFee;
c_0xb095bd59(0x16e880a55f112806eb50f7fe1d18221776e50a929ab0592458c513bf433f835d); /* line */ 
        c_0xb095bd59(0x87d526bc0e53b2b47d6144179494082d766140fba4c4211fe78aef56232a38ff); /* statement */ 
durationBeforeExpirationTime = 1 days;
c_0xb095bd59(0x696fcfb842684322fb896cfd9ab88f79d676cc0b177506b318953f6f144ec499); /* line */ 
        c_0xb095bd59(0x7fe1d4247f399a5cf5d8681ee5242a25003dba6d4ac3846efa31fd028d21f0ae); /* statement */ 
dailyLimit[address(0)] = coinDailyLimit;
c_0xb095bd59(0xecf13cf73ffb169e59614182a19fe4675b14fef95c05a2b378692368d43fa50e); /* line */ 
        c_0xb095bd59(0x0c2f065c32421d35eda4a7773c3a0518466ea8961946be9da45a84219af5f6ac); /* statement */ 
dailyLimitSetTime[address(0)] = block.timestamp;
c_0xb095bd59(0x7ec326d92e794e2620ee9fb77093a615c9c598f0701967402789db8e26a92317); /* line */ 
        c_0xb095bd59(0x3e194d83ead081e304daf3488dbde6cfea68e9417eeb06d88961b4341bcf10bb); /* statement */ 
transferNonce = 0;
c_0xb095bd59(0x442f5a5d7e75b9d4a2c804d6cc18898ad3573f052001467fb98646ce60d5dcc0); /* line */ 
        c_0xb095bd59(0x0b67dcc8402a262d5bbc19fc6675a59396524f5de4da284a14216d8a515a9790); /* statement */ 
tokens[address(0)] = true;
    }

    receive() external payable {}

    function transferCoin(string memory receiver) public payable {c_0xb095bd59(0xe8d678e3abbb74bb0a5f025d026a01a57e4639c2f01abcf6c5ec852a9b144d50); /* function */ 

c_0xb095bd59(0x5da3c53970245c88ce3638e4067290d679b89d78ca82fd57992d8379b11b7a73); /* line */ 
        c_0xb095bd59(0x1d7aca7e0b9cad34f2fbc776dcd187f3971a24ae7bd4ef43a6012c2cf27d1af3); /* assertPre */ 
c_0xb095bd59(0x99b43d6cf4926cd3a6243eddb5864589b161f0da4f414ab6b439debfdbc5a74d); /* statement */ 
require(
            msg.value > 0,
            "You have to attach some amount of assets to make transfer"
        );c_0xb095bd59(0xdee809ff0e352ce8aa516a66b8cc3d97645ae736badbf97ee298cb6ba3d14061); /* assertPost */ 

c_0xb095bd59(0x1be26dd078dc71a3c318ab5d819e4c29848e9a79384e769ef15148c7283ab74e); /* line */ 
        transferNonce++;
c_0xb095bd59(0x4fab3d145fe84ef7a3d2fc868c53e842f600cd512aa22c4e817940399eb7fd10); /* line */ 
        c_0xb095bd59(0x034ddc10eef7beb0e2d3bbdb56117ddad38f6fcf93bf2da9fe51a4df783dd095); /* statement */ 
emit TokensTransfered(
            receiver,
            msg.sender,
            msg.value,
            address(0),
            transferNonce,
            block.timestamp
        );
    }

    /**
     * @dev Request for swap coins and tokens
     * Can only be called by the worker. Works for only for expiration time interval,
     * for added token address, and validated signatures and for assetDailyLimit no more than
     * initialized
     * SwapMessage transferInfo to see type SwapMessage
     * bytes[] signatures - array of hashes
     * Can only be called by the worker.
     */
    function requestSwap(
        SwapMessage memory transferInfo,
        bytes[] memory signatures
    ) public payable onlyWorker() returns (bool) {c_0xb095bd59(0x2b0eb12e4a8a8d8db345808fa29aec82b2c0bf21f114424de144d419e3b666db); /* function */ 

c_0xb095bd59(0x71e9b7d60f07a7713f26e5510ad828ec3ab7e1bf03db8cf836b089d3198fe390); /* line */ 
        c_0xb095bd59(0x76ae843649f2d83f51c6b50de3416e9973d98ae2a2ed4f2b10307c0d42887133); /* assertPre */ 
c_0xb095bd59(0x73ff4302788dd8b86fcd888eaad25c32167e2613f31b0a0d4c7c4b6b2aae4016); /* statement */ 
require(
            isTimeExpired(transferInfo.timestamp),
            "Transaction can't be sent because of expiration time"
        );c_0xb095bd59(0x60cba01f18f57409e152d5f7b6e7cedbae1a14481c561f6b6f60a2bd4577f0ee); /* assertPost */ 


c_0xb095bd59(0xe7745f1f1f9067f39e569849e3d4d69c9c8cb1870bd5a6f8985a577c881e128a); /* line */ 
        c_0xb095bd59(0x38b0da058531af18711fc0fa6e6b7cd7edd73059ae9de4fc2102d1a6f0dd093f); /* assertPre */ 
c_0xb095bd59(0xa7020490e1c808957e6da0c76d18a92018260d88111619ee19774cf54f18a4de); /* statement */ 
require(
            tokens[transferInfo.asset],
            "Unknown asset is trying to transfer"
        );c_0xb095bd59(0xf1cb3747071fae7ac0e1ea9f064e5efeaffd271e628b58093c5555eb806afbae); /* assertPost */ 


c_0xb095bd59(0x66350439d0c54f2589f7049446c04c8c423eeeac538cd1eba508bdf822401b64); /* line */ 
        c_0xb095bd59(0xe0f009e9ba9770035c63c1fc9b831eeabf43eee344f98731e2eff9363dc0bbe2); /* assertPre */ 
c_0xb095bd59(0x442aefd17b64788a5b313fcf9e3455fbc91bacf244a606c830856246312fe2de); /* statement */ 
require(
            transferInfo.receiver == address(transferInfo.receiver),
            "Invalid receiver address"
        );c_0xb095bd59(0xa05509ff22b2b30325495768bd17090723ba90249cc8a8fa39cb102f90a42eac); /* assertPost */ 


c_0xb095bd59(0xd365c6e3f807e05f41e58c7ce7c1e149fbfee7c2ce0eec21cda2f6711433c4c0); /* line */ 
        c_0xb095bd59(0x99760e76443cdfea18023ddf6fb20ae9914caf60d4d42f9f76e54c53c51ccedc); /* assertPre */ 
c_0xb095bd59(0xd28e1103e4de5fb925870f4358638fad1917472ee3e65955da8471d5c5bfc98c); /* statement */ 
require(
            signatures.length >= signatureThreshold &&
                signatures.length <= maxValidatorsCount,
            "Wrong count of signatures to make transfer"
        );c_0xb095bd59(0x88d829137f24c4cabd0ca5b5d00d17ec5716a35360d7d301e3a81e9b01637ae4); /* assertPost */ 


c_0xb095bd59(0x78aa0fbe8004ab6e99a8613fed96933de6395ab95ecec7a762f009250da78595); /* line */ 
        c_0xb095bd59(0x557f51780995af18ac433ceaddb868d49e4a8aac7f6ac3dc79e314d879905abb); /* statement */ 
bytes32 signedMessage = this.hashMessage(transferInfo);
c_0xb095bd59(0x21417f169203df12f78f6efd3babfbe4334f9e52307a0dcfc969411ea5201c9d); /* line */ 
        c_0xb095bd59(0x751b5723796a9db1946011a6805c2c280af2d8a8646b765a11caf1ad65bc77b9); /* assertPre */ 
c_0xb095bd59(0xb69e5a3fc01d55d6a177cb9cbeec639352479afd4ca09545c89345258ec4b9df); /* statement */ 
require(
            verifySignatures(signedMessage, signatures),
            "Signatures verification is failed"
        );c_0xb095bd59(0xc25cdd2619701e98ca756a38cdea6de926b7a08afe9a1fa3ea6083220a07e80c); /* assertPost */ 


c_0xb095bd59(0x715ea836d5d32dabfc4d25785cc6a7c6b0ad4add9e131d7128f67562f29c46b3); /* line */ 
        c_0xb095bd59(0x244e51e099caaa6e31529b64f40e071ab5241706aa8bd9518fc8be6eafa729f4); /* statement */ 
bool res = makeSwap(transferInfo);
c_0xb095bd59(0x5f37423ab9b85c4ea810cf03ce53c406e6969d190e5898045437de63f4c43eb6); /* line */ 
        c_0xb095bd59(0xf9766ef35781ac149d06f6b68f62d007c1e5edc4d742f0bce763d4ae1fa67545); /* statement */ 
return res;
    }

    function transferToken(
        string memory receiver,
        uint256 amount,
        address asset
    ) public {c_0xb095bd59(0x084594e73237d5992fee23d77f919ee3e7e2e662c631878c0b42e98b8db7a51c); /* function */ 

c_0xb095bd59(0x5bbd4609b256d1a3c4227c12677ab9319e14fcb569ab8d179a65916a774e9059); /* line */ 
        c_0xb095bd59(0xaec7940b8bf15df727ebf60df513c96a3f0eae6349a7fd407668438dcd231e67); /* assertPre */ 
c_0xb095bd59(0x4c73807ac03504b0e56a80d7f1ee5974d0a30b558dbbacaf00ce9030602a9026); /* statement */ 
require(tokens[asset], "Unknown asset is trying to transfer");c_0xb095bd59(0x43c1131ac98c8a9ec929867cec4f8b848f96b601730d20940b9b2af8c21db7bb); /* assertPost */ 

c_0xb095bd59(0xae54be994f77e71621d56cd29b0c11edbf07c0da7037b79e4ab03eb4afa07252); /* line */ 
        c_0xb095bd59(0xf44907e246e2f470ad6adb1b0b337ad6ba351f1e66d92b9e8ab294ee09985c45); /* statement */ 
EdgewareToken assetContract = EdgewareToken(asset);
c_0xb095bd59(0xc67bd7345e593f78ded95e9b15ff64a3f3a8c7a963207d204b9c79631551d0c1); /* line */ 
        c_0xb095bd59(0x09579620f5bdcabefb5c7485753ab5f57685e09b9c3fbbf6f0ff86c70af6bd98); /* assertPre */ 
c_0xb095bd59(0x9db67ecd9e314868329c6994f39c04929284c99364c8364bf45106351f3c09de); /* statement */ 
require(
            assetContract.balanceOf(msg.sender) >= amount,
            "Sender doesn't have enough tokens to make transfer"
        );c_0xb095bd59(0xe51811144260bd95bbbc1f7ed4a2a4e0bc21827f0d0030707e5a2b0f35cc878b); /* assertPost */ 

c_0xb095bd59(0x319a3dc383b41fc9be2e76feb501163d37e8a7ea256fc5a8cfa1b92af2f0a394); /* line */ 
        c_0xb095bd59(0x65f28cb7a4a1e6e90a632eb7da344f5ab3e3029dae05b0daa586da34ad98c17a); /* assertPre */ 
c_0xb095bd59(0x9bd8b5a543f03d19eaf0a4ac1f64523623d727afec81a0bda6833ac1144230f2); /* statement */ 
require(
            assetContract.burn(msg.sender, amount),
            "Error while burn sender's tokens"
        );c_0xb095bd59(0xcffaabc1901daa8114f2da849983fc5aae9d68e7510c1170b3ac2dd2e4508cff); /* assertPost */ 

c_0xb095bd59(0xe4d24c6ab446cd3e4cd2aed0c3c42b5ed645a4bf916763fc77f7ac5f94629997); /* line */ 
        transferNonce++;

c_0xb095bd59(0x9efd584797d8854711e5ccafb1f70dcf1024423f0919547b98b3b49905f9ac77); /* line */ 
        c_0xb095bd59(0xfe197e06205c40d9ff4066ff3137d2d3ddc4dc621090abc3f1d10eb161be9234); /* statement */ 
emit TokensTransfered(
            receiver,
            msg.sender,
            amount,
            asset,
            transferNonce,
            block.timestamp
        );
    }

    function setFee(uint256 percentFee) public onlyOwner() {c_0xb095bd59(0xb1ffd54493d776b9e05d2c0a2a17a78f17762cefa4874655b97b3aa0cb238708); /* function */ 

c_0xb095bd59(0x21fd27bf316cd48224d66f7b5e0d33d78c1abaf7b879fca6b039e70159b847bc); /* line */ 
        c_0xb095bd59(0xf87a6396a32f21f26914325a073afa8609b09e36acc3dfbdd8b476fbe95679a0); /* assertPre */ 
c_0xb095bd59(0x35d438044684fa0e2aa9502b9b7de87ba34887e6e7deccd87b497b3a90f604ac); /* statement */ 
require(percentFee != 0 && percentFee < 100);c_0xb095bd59(0x7e40f974cb8ba0dd8ae22e18e310620f56a548c7643f668069dde4e049c536e8); /* assertPost */ 

c_0xb095bd59(0x330018b14b469bf081feb4b8a3c2ffecc9c6cf782016ef127aeac7eeaa6f1857); /* line */ 
        c_0xb095bd59(0x7df879df57d439b10df23501d7728ecdb05fe1e3f1213afa91d4f11fb760c822); /* statement */ 
fee = percentFee;
    }

    // Is count of validators need to check?
    function addValidator(address newValidator) public onlyOwner() {c_0xb095bd59(0x118062c78ab1a51ea57c7bef8b6330a9a0124213643c810865d51413bd3f03e1); /* function */ 

c_0xb095bd59(0x12f7a2e9bc6ef78e9cd7a60dfd97a958a65c7dae50939ac2921baa4df45acaa3); /* line */ 
        c_0xb095bd59(0x8a28290c55383141ce1d703088d0b2db59bf6d20b7d076aa7bdf6f6efc70e1e1); /* assertPre */ 
c_0xb095bd59(0x46737905f881a7042caa6b551c747f2b07d476b27697cf4ddb63e03393009f2c); /* statement */ 
require(
            currentValidatorsCount != maxValidatorsCount,
            "The maximum number of validators is now!"
        );c_0xb095bd59(0x08dafe35a8cf3dc1295c89aa986bc653bd160d50211b01ca23afd6260192f0d3); /* assertPost */ 

c_0xb095bd59(0x76322d3839a7e0663036dbf019805d1e76dac616b98b4e3c87b2f5858403ad76); /* line */ 
        c_0xb095bd59(0xd2a84615e619aa066af7c24eacc9724b663f28609bfa62a76422664c5bb92780); /* statement */ 
validators[newValidator] = true;
c_0xb095bd59(0x91f306f2fa8fad4eb20317118dd25f716ed95d2552d3be9e4c0b4c2d1343e06b); /* line */ 
        currentValidatorsCount++;
c_0xb095bd59(0x2286d62d3ff6cb672a370859c01f5f9eb5263c8ebd9e18e161cb7f009921b1f4); /* line */ 
        c_0xb095bd59(0x4112d96c28710d630863f1bce1f11858a93b6ea955e705fc0c7050ec405f450b); /* statement */ 
emit ValidatorsCountChanged(
            newValidator,
            validators[newValidator],
            currentValidatorsCount
        );
    }

    function removeValidator(address removedValidator) public onlyOwner() {c_0xb095bd59(0x2f7d9461c89d9a55eb162ad2ee0eb60d29ae21ffbd394e8aa7fc1059ff94e991); /* function */ 

c_0xb095bd59(0xcc14351eb82a4b0df07e5665b65e5d36b8b1dd7fa59099863710509a2f20cfda); /* line */ 
        c_0xb095bd59(0x370bbc113f3c008ed8f66de46cd886cdf794390879e832e31314451912728fd7); /* assertPre */ 
c_0xb095bd59(0xe1b0b8d94c353411fa089e4efed8645a801d3b0af4b850c83618a4e9baf8258a); /* statement */ 
require(
            currentValidatorsCount -1 >= signatureThreshold,
            "There are no validators now!"
        );c_0xb095bd59(0x59459cb01f7abef554f823759a9085c4820623f961ee176adf71570af858d063); /* assertPost */ 

c_0xb095bd59(0xee0573f21a0f2f697fa2b40eef3e480d374a4b98c4ed571183cb85d9351eb749); /* line */ 
        c_0xb095bd59(0x1d77e224ee9a9a9496327055918a42897ca580f2ddc255cf22cc1aacfdf3ae7e); /* statement */ 
validators[removedValidator] = false;
c_0xb095bd59(0x3217bd1fa6366b6e5bd21b256bc7db7f07c26bd74711195102cb6864b46a6d29); /* line */ 
        currentValidatorsCount--;
c_0xb095bd59(0xdecb55f7db2e8d52ac7539f533ff80d029db07a14392e3ef22c4569fc988e585); /* line */ 
        c_0xb095bd59(0x1b34f1c1d9f12ddbd18b8b3bfcb7a9f125a08d53f91af89daa925cc49095345d); /* statement */ 
emit ValidatorsCountChanged(
            removedValidator,
            validators[removedValidator],
            currentValidatorsCount
        );
    }

    function addWorker(address newWorker) public onlyOwner() {c_0xb095bd59(0xa631e51e3e19503c2087f98c884dc38ec6f5349e5af34c44dc620cfa1032cc7a); /* function */ 

c_0xb095bd59(0x3f430e3062ec6e15c7fb34dab92c8ec6a3e32110bf1f8fbf1f6fe4503c4f1045); /* line */ 
        c_0xb095bd59(0x3ee497a88c24ee71731adb5df1664c8581c88d4a2627318e1bc964dc30b37c5a); /* statement */ 
workers[newWorker] = true;
    }

    function removeWorker(address removedWorker) public onlyOwner() {c_0xb095bd59(0xc739d3d58d4c8316657a69cc275df3f95fb31587c2261a040cff3870dc16ba19); /* function */ 

c_0xb095bd59(0x9103ab39eaae533db81df6fa07c82361485dee0c30e98bb3c9141bf84868287c); /* line */ 
        c_0xb095bd59(0x068e7739de102586246d6b7474ae50a706e7bffb2f6b8e308fb4651c04017274); /* statement */ 
workers[removedWorker] = false;
    }

    function setThreshold(uint256 newSignaturesThreshold) public onlyOwner() {c_0xb095bd59(0x8a93092b315e0307b87f6a60cabcef186abce987bbbbee0bd79e25007f4cf093); /* function */ 

c_0xb095bd59(0x3fedb6d35d4c4546b43be6bde6a964601849f90446ebbb9d4d8902dcba3d2086); /* line */ 
        c_0xb095bd59(0x25119c637495f2e4885d47506e7a469ea3089f7d1a2baa8bfeb196901636c05e); /* assertPre */ 
c_0xb095bd59(0x43f7e46476d9e6aafe873754dd4de7d185f4e168e29305453b5394578698645b); /* statement */ 
require(
            newSignaturesThreshold != 0 &&
                newSignaturesThreshold < maxValidatorsCount,
            "Ivalid number of Validators"
        );c_0xb095bd59(0xea71c4bc07fb86952148adf5e125bce758f12a5467e7c79ff09de9716e7b4fe7); /* assertPost */ 

c_0xb095bd59(0xab065848b84f87efd50ee599ee6eff9c03dda8f7f870a108d4f03e12fab06a77); /* line */ 
        c_0xb095bd59(0xf7cc764ddf5f8bbd6a55be7438fba934457c92c56f17ece6504ba7625abae649); /* statement */ 
signatureThreshold = newSignaturesThreshold;
    }

    function addToken(address newToken, uint256 tokenDailyLimit)
        public
        onlyOwner()
    {c_0xb095bd59(0x313d61b1e356d1185098d9577a553bac5a8f45cb25b6f156e4672bd9c02e2adb); /* function */ 

c_0xb095bd59(0xcd632fde2e88f569957aa3a388c5de0519d742d638ff73268417d6bea5cc33fc); /* line */ 
        c_0xb095bd59(0x0c3bdaf5b10ff83e8cdf9e177312b2d928513aa08455dd148e28523c372ba883); /* statement */ 
tokens[newToken] = true;
c_0xb095bd59(0xafd58bcff40c410e98300866fcb494b33abe57824913735d1cb19158412a8397); /* line */ 
        c_0xb095bd59(0x5e6e47642970fddc8f974a71074dbadb7df29bb59026deff8443dd6b88529a54); /* statement */ 
dailyLimit[newToken] = tokenDailyLimit;
c_0xb095bd59(0x41b04b893a867e50da6bfc8b37ac62cf4c04303f475b11f938c1b821fa543b21); /* line */ 
        c_0xb095bd59(0xe223b24e241ae999927f8cf3d74cdd3d5931c7377878f93de2c12d07791a748f); /* statement */ 
dailyLimitSetTime[newToken] = block.timestamp;
    }

    function removeToken(address removedToken) public onlyOwner() {c_0xb095bd59(0x315881324ad25450fa553d078327170901344fbdf6bed355c7ccc0c2aac59698); /* function */ 

c_0xb095bd59(0xc3920b0bda70d4c1542aa34a3da6eff7d0a5b9abcae9a9cbcd36caec1ddcff55); /* line */ 
        c_0xb095bd59(0x9a66ec02c8051c66679f449d109b020cb3e6472b87ca59186f734a8fbb10e86c); /* statement */ 
tokens[removedToken] = false;
c_0xb095bd59(0x0880001d3ab1c16f7f53d312b1cb1b3461706b85d831f645d2f298053e4ada1a); /* line */ 
        c_0xb095bd59(0xa518de27b5ba083e49f4bdf20098d59214da3d8295cc9c54df6e393a9321432f); /* statement */ 
dailyLimit[removedToken] = 0;
c_0xb095bd59(0x83e36b31743219f088402f24ed137f669043931f855828b4e9a3e7534d05c494); /* line */ 
        c_0xb095bd59(0x69753b569650b921f54caa4dab81cca4acff41e22e6dc6d291286422ab932110); /* statement */ 
dailyLimitSetTime[removedToken] = 0;
    }

    function setDailyLimit(uint256 newLimit, address assetLimited)
        public
        onlyOwner()
    {c_0xb095bd59(0x75a8b01367fa744fc329f28944bf15f9843f833049d538678ebc2f590f87b9b5); /* function */ 

c_0xb095bd59(0x7a7ac92d90e90964638da12c38e214e6dbceb99a7b7f125a0779b070bfd599d0); /* line */ 
        c_0xb095bd59(0x93f2a8b2e5353e1ca9357939ae96ed21919f9291fc72285735a24367a0f4165f); /* assertPre */ 
c_0xb095bd59(0x53e02d6f2bba148985883f0f4a3efbdbe63e9ec81f0ce17e304a323a43b5cd7b); /* statement */ 
require(newLimit != 0, "Invalid limit");c_0xb095bd59(0xdd4fa96ef416c3f8717a9922eab8c6fb9726e1767c896f14f31a2d7606e95b52); /* assertPost */ 

c_0xb095bd59(0x674eb78505bd9ffd421cc5085a060909c45ff4967df19ee5e2583d9c0a9f538b); /* line */ 
        c_0xb095bd59(0xaacea7c4fff80ef1ec2dcf2225e02a326301fde8a020e72e81a8b20e0653a025); /* assertPre */ 
c_0xb095bd59(0x7e691c153ee0b25af713054f11420ddee25b8d5f924586c57a13862721f2ecdb); /* statement */ 
require(
            tokens[assetLimited],
            "There is no such an asset in the Bridge contract"
        );c_0xb095bd59(0xa4d622d93a089f4dd3c68a3e0807a331c38f4974ee4f03f6ba47b1e36641f433); /* assertPost */ 

c_0xb095bd59(0xd1dc45af3496449335d8866dcdb915ea5adecc34acd18afa1d244e3de92b271c); /* line */ 
        c_0xb095bd59(0x6afc187fcab035a9369d3e5ec12f1ee821c3cfe332b68d3d0b33d07d4bc69327); /* statement */ 
dailyLimit[assetLimited] = newLimit;
    }

    function setNewDurationBeforeExpirationTime(uint256 newDuration)
        public
        onlyOwner()
    {c_0xb095bd59(0xadef2a4672ae757c126272ab8700964297467e6239bbcb72e0ec1ded91d347b6); /* function */ 

c_0xb095bd59(0x51a2b711229c155ecef3b0fa68d1fca687727e983648b8af4382704fb6b65cd9); /* line */ 
        c_0xb095bd59(0x801c7dce3146ad27c526118dd34941e076dd57a816785aeabd758889eec81ead); /* assertPre */ 
c_0xb095bd59(0x518c9e0b7c43c2c726d9cc8f527f49d56922438127270a6e086ea31add2d5bc4); /* statement */ 
require(newDuration != 0, "Invalid duration value");c_0xb095bd59(0x5d182d1b02c9c1cdcb6cb25dc76c9058982a1d707fea6b960a9ac458f358361f); /* assertPost */ 

c_0xb095bd59(0xb03415619d575da64ffb28277586c9a92c50395692ce355ac0b0509861422677); /* line */ 
        c_0xb095bd59(0xa982e600b47aadbfda226e3ba0c5e528e4f660d23a7620ac4085e4b7f064c3d5); /* statement */ 
durationBeforeExpirationTime = newDuration;
    }

    function hashMessage(SwapMessage memory transferInfo)
        public
        pure
        returns (bytes32)
    {c_0xb095bd59(0x30ba2a8395b5f415fdee25875c74031b6d64d2a6253d22f9918a4fdfd48c2a42); /* function */ 

c_0xb095bd59(0xd2adb9b7ad02b0a9714b55f0b98c3e969cb8574e3b9d0124cef72800abf467ff); /* line */ 
        c_0xb095bd59(0x1ee51a3a82b9df62b1612d5205debf68c232928f77829d1a1bf239cadb185b5a); /* statement */ 
return
            keccak256(
                abi.encode(
                    transferInfo.chainId,
                    transferInfo.receiver,
                    transferInfo.sender,
                    transferInfo.timestamp,
                    transferInfo.amount,
                    transferInfo.asset,
                    transferInfo.transferNonce
                )
            );
    }

    function isTimeExpired(uint256 txTime) private view returns (bool) {c_0xb095bd59(0xe49120bd1419a320370f83af43cc93d989403965c96da91f1e38e5780a381ea0); /* function */ 

c_0xb095bd59(0x9f0f7d82938cad1ddfea9c04f2ccc83188ca5ac5929ab2f1e3024e908fd6d8ef); /* line */ 
        c_0xb095bd59(0x85548281197f29b85442923765c424ff2450ead0ab78dc6cd33568076fc10238); /* statement */ 
if (block.timestamp.sub(txTime) > durationBeforeExpirationTime) {c_0xb095bd59(0xb66c1003de89d04e0897497416b0abddfe4842d9d1d7e24f7ee47fe260394420); /* branch */ 

c_0xb095bd59(0xcd038fa81f60aa4668c536ea1256731427e6ad1df35c3755311f90b02dea5621); /* line */ 
            c_0xb095bd59(0xcf05224bb2468222bd1604f2b749777406c0ad50c418892af2aa22d605862a54); /* statement */ 
return true;
        } else {c_0xb095bd59(0x382cfa8f038e5aa687c34d9e691efe200a6838aff79a73d6ec2050fab2b6a716); /* branch */ 

c_0xb095bd59(0x23c3d0bc43bc6ec07211038ea6f0ff7abd1ad7e61fad0aba7bdcf7c014acbb00); /* line */ 
            c_0xb095bd59(0xb150c070aa7a71614be6d516c3fb02408e9a0bae770c02d441752e5b8a5fc5ca); /* statement */ 
return false;
        }
    }

    function verifySignatures(bytes32 signedMessage, bytes[] memory signatures)
        private
        view
        returns (bool)
    {c_0xb095bd59(0x3860579ca431e93441ba5813f7f32d1778210d9c75a60f27d128151e82deddce); /* function */ 

c_0xb095bd59(0x4c7a9993ddf4a5fce571457099342f19016e6715d3dc5362f2e572fa3da3bcdb); /* line */ 
        c_0xb095bd59(0x46c3a4a9fa3eb8f1e4d4a1b4d87b714ba3e4faf318120c3857505c753e426462); /* statement */ 
address[] memory signers = new address[](signatures.length);
c_0xb095bd59(0x83626aae79aed3dae83c2a4a1517d8be6fe10676971fcaa469fd5ba8783e25e9); /* line */ 
        c_0xb095bd59(0x263c419020d1d45eae3ab7f0df523ea4faf5713c3153ec66ac4e74936b4976a6); /* statement */ 
for (uint256 i = 0; i < signatures.length; i++) {
c_0xb095bd59(0xe079c66c18cc962c6380bc73d73440968bd09524f54320f2bed380234ac3c618); /* line */ 
            c_0xb095bd59(0xe8499c54d761b5cbe1e01758b0b43ae5991752448027770ff15ba84016254743); /* statement */ 
address signerAddress = ECDSA.recover(signedMessage, signatures[i]);
c_0xb095bd59(0x7b8e263fe9ace883aa245c5e9f828a1a9f8f79612f72d006f68b791c0d14f11d); /* line */ 
            c_0xb095bd59(0xa361c349daa1f8c106c3297c439657ca863b19b9c4ff2d2571b193a6217d8a98); /* statement */ 
if (!validators[signerAddress]) {c_0xb095bd59(0x5d02f048c2e7b83ce8b26f3e5de9498ec3725d8e2a705622e78ece2d857d688c); /* statement */ 
c_0xb095bd59(0x5311144acad519583ce62db2fa1aa81e6536858cc07c9ccfb39d2243c8a204b9); /* branch */ 
return false;}else { c_0xb095bd59(0x43a87af029579d91cf3cef677ec75819458c5ad286f38da2b3bbe9863bcb04dc); /* branch */ 
}
c_0xb095bd59(0xc757815ffe9403af9829ae51177ac94509c782e0b9ac6291c66da0072ee634b5); /* line */ 
            c_0xb095bd59(0x61eb19dd725b6c70bca0023aeb67258beacb523b610d8c415c08dd8f7dc7f9a0); /* statement */ 
if (i > 0) {c_0xb095bd59(0x6bd1cedf71e100fe0222def2ffac884022259c7f44816d1a5fad623678947269); /* branch */ 

c_0xb095bd59(0x4b306443563bf7aa51771d425200a4c4e55758be00a481e3b91137eb8eab6117); /* line */ 
                c_0xb095bd59(0x55f6ce27f71715d6a5052f9035ffe68fdd3dcc479c8a33cb28a986662ac54118); /* statement */ 
if (!checkUnique(signerAddress, signers)) {c_0xb095bd59(0x5b1dbd11d87762410224113c3189934b3662bd40039f4210828c4da06224d697); /* statement */ 
c_0xb095bd59(0x30bfba803b99aef6a9fab7f170cbe5cfd6d824d0d04c2c528caad3933c6545eb); /* branch */ 
return false;}else { c_0xb095bd59(0xae21c534731f54967a03dabf7d8416b2ca57657de8be08926556b38a3ded594c); /* branch */ 
}
            }else { c_0xb095bd59(0xd3f8285c863bc0ccde7a53b27f840ef204062716e0764c1ec2bfa611c8ef83fe); /* branch */ 
}
c_0xb095bd59(0x38a81e399efeba67762c81994a2ec2db4605245a323f346c45b6cb96bb01b92b); /* line */ 
            c_0xb095bd59(0xdf906d1d5b90bab14c2b12eb14ce3225590414e304ad447c69d8124f96505d4e); /* statement */ 
signers[i] = signerAddress;
        }
c_0xb095bd59(0xd6796311309f8a4690ebdeb750ae25b6d67d50ff44e680f3ac010bcb44bc0ad9); /* line */ 
        c_0xb095bd59(0x227ec30a16b08d1890fad61bce1ed5fa5e07e14737cc429c73ddc15a485924de); /* statement */ 
return true;
    }

    function checkUnique(address signer, address[] memory allSigners)
        private
        pure
        returns (bool)
    {c_0xb095bd59(0x0128992263fd0fcf5a17c77c4bbc2e883a8d773a00990a99fa593f22a68c1b90); /* function */ 

c_0xb095bd59(0xcd9a10402792195e057e3e6870bbca13ca3fbd8bfdbbe1847099c5cfbcc63f87); /* line */ 
        c_0xb095bd59(0x891142cf5d5404cfc0b928923e7e645ca3f6ea4eed7bcf8441805aa04a95a377); /* statement */ 
for (uint256 i = 0; i < allSigners.length; i++) {
c_0xb095bd59(0xc5b8dd29eb81ab273fded71f4577a8dcbcbeb7aa5b7b950255485da7eda9475c); /* line */ 
            c_0xb095bd59(0xa08bcc45da9a91035351393fa8b346b57206695b41371c9bb5b694327d5bbb3c); /* statement */ 
if (signer == allSigners[i]) {c_0xb095bd59(0x91c0dacf681d7d3810cb6dad0c9a59af055598719e81302169f2efbfbd12988f); /* branch */ 

c_0xb095bd59(0xf415daf483921f6963f539b5f4dc7b551709fb603fe264c516557a25d2635715); /* line */ 
                c_0xb095bd59(0x5c07cdadb26955ba595cf252c54131e84c85da6294d6eed0e03d24c9897ad107); /* statement */ 
return false;
            }else { c_0xb095bd59(0xd59231e62e44b34aabc2cfe7eec0168d43a9a525755b92de22deaba87e375a39); /* branch */ 
}
        }
c_0xb095bd59(0x15e12199b3be4105d9bff2e166c7f58f2326149813a9e8c752dbb3e56b45b4cc); /* line */ 
        c_0xb095bd59(0x296749874cc1325beedb20bf64cdbc53be364113eab1bc5ad22c504a97f2271e); /* statement */ 
return true;
    }

    function updateDailyLimit(address asset) private {c_0xb095bd59(0x620ae6ab0e21b0cf0ae21ce3b9ad82aaeff01fc0383ca7960413c095f5cd86f8); /* function */ 

c_0xb095bd59(0xeceea605cfff1525cd4858385e320319e4afcc6efcbbeede0e112a615e0aa4a6); /* line */ 
        c_0xb095bd59(0xa4890a4c645c6d7decf81f2f7b20fb8b13d919a36bbcc220b82daf47800b4960); /* statement */ 
uint256 currentTime = block.timestamp;
c_0xb095bd59(0x15c8f01fbeeef100b8a5bec9cdfe67715f9ddc4fb91813cc0c6d9c79ab4cd8ec); /* line */ 
        c_0xb095bd59(0x8df29dbe3cdc31b7eabf2ab221f770558d8516acd1d3939688d230ad28e704c5); /* statement */ 
if (currentTime.sub(dailyLimitSetTime[asset]) > 1 days) {c_0xb095bd59(0x16bdedc51238b8e4e32dc3b4e61e24a9095d7fa7da9f2962ad4683d2e46f1485); /* branch */ 

            // we don't check dailyLimitSetTime on zero because if execution came here token already in tokens mapp and dailyLimitSetTime also filled
c_0xb095bd59(0x7a94bb68db34f464312cbec30df4329c69d7781d668ed26dfafc7aa24d5ee2a2); /* line */ 
            c_0xb095bd59(0x862617443310b235bbd6ae3a38e2b43240ebe3d15f1fe71f810f6df3e6379071); /* statement */ 
dailyLimitSetTime[asset] = currentTime;
c_0xb095bd59(0xa30174b264bdf6d1b1f76c1a5181f846f9e8b27d71fe9a2924b91ff7acd0b4be); /* line */ 
            c_0xb095bd59(0x77a95afe4c866351559f5ceb2a5c16d50e9fd4df86fc784c506a1b8e1a71e7aa); /* statement */ 
dailySpend[asset] = 0;
        }else { c_0xb095bd59(0x065b7d497ec3838ef56db06d364a879ca50979c44afa76522f10e2117b540365); /* branch */ 
}
    }

    function makeSwap(SwapMessage memory transferInfo) private returns (bool) {c_0xb095bd59(0xac52c5bcb9b42dbf9a58998fe6ad675f1571f377ed218179f658eaf33ef50ff7); /* function */ 

c_0xb095bd59(0x59b231723ee22f5c586a26bc4301a776934dce6f0a5901afee3aeae219cd4d0e); /* line */ 
        c_0xb095bd59(0xbcc9f053638cefb27269f0bdc2e20404e60524a4a93d339bd8ed4d0871f1eba2); /* statement */ 
uint256 assetDailyLimit = dailyLimit[transferInfo.asset];

c_0xb095bd59(0xae060559bd398569f7105be8f1ff641b0ce6518bb73b9d7ec4c389d4a9c75703); /* line */ 
        c_0xb095bd59(0xb876c3127e1dc71e8b484af9cdd67aef1f13995bbba29a558547515429cae63c); /* assertPre */ 
c_0xb095bd59(0x210388b3d510fc2275e0b558aa218be2ac5608b99f26054484ef56e13f377b17); /* statement */ 
require(
            assetDailyLimit > 0,
            "Can't transfer asset without daily limit"
        );c_0xb095bd59(0xfeaf3cc391f52fac3c3ff18b224b9ed0ed59714b852d678b54e9fa60f7c8c9a8); /* assertPost */ 


c_0xb095bd59(0x0dfc1444cbe914e3fbd6621135b1742812eaa977ee73df6bb9ffdcc61a2ee03b); /* line */ 
        c_0xb095bd59(0x72f353e2c6ea2f9def19d4a55129804cf3032f082797345d1035b1bb8ce04f89); /* statement */ 
updateDailyLimit(transferInfo.asset);

c_0xb095bd59(0x9a91218b6a3aab8937a25fc56dedeb65fa32c3552a70c2ef14ca517bcc791f9c); /* line */ 
        c_0xb095bd59(0x75e787000867f4e416e21a0ec8f7361c1cc2ef3f0f797b56976fb82c6aafa32b); /* assertPre */ 
c_0xb095bd59(0x34022d57303762e21c9abf0e806748644d10143b01165ec6df6d859b7d56cd8b); /* statement */ 
require(
            transferInfo.amount.add(dailySpend[transferInfo.asset]) <=
                assetDailyLimit,
            "Daily limit has already reached for this asset"
        );c_0xb095bd59(0x569df53a07b6c3d45ce87bc359e83b4f901865851fa56d9a7cc7eb012d41925d); /* assertPost */ 


c_0xb095bd59(0x961a26072b90ac1118172e1fb42fbab8e40220849e5034b69b96be3bd5921df9); /* line */ 
        c_0xb095bd59(0xc5e4040d1ba99e87da7ec548ca16b0f7bcc0d93ead964a578df70364ca08cfad); /* statement */ 
dailySpend[transferInfo.asset] = dailySpend[transferInfo.asset].add(
            transferInfo.amount
        );

c_0xb095bd59(0xe60db83e73afd6f5a5acf119d5ef69bdb2ec09a61b204896369f0bf9b5bc49ae); /* line */ 
        c_0xb095bd59(0x01b38dd6cdeb72983da5894ecd35c8b272e9bc25c0f2279030767c0e610e00d1); /* statement */ 
if (transferInfo.asset == address(0)) {c_0xb095bd59(0xd04496f38fa444d2ee4bafc03dd3b76166e2ce44ab78330c5d8bef9668b64fc3); /* branch */ 

c_0xb095bd59(0x87aa7f01b297bb21508b45693a8ca99881396fbd9d0bdc5762a50e1283d379ba); /* line */ 
            c_0xb095bd59(0xb416c6ac2f809dfc18b344acdbb742011e87d29aaed17213cde45e9c7ffcd1f5); /* statement */ 
uint256 amountToSend = transferInfo.amount.sub(
                transferInfo.amount.mul(fee).div(100)
            );
c_0xb095bd59(0xc38812f90eaf5b1a1c5c69c2ab59090ec0a9620533992488d87e7185ba57ac82); /* line */ 
            c_0xb095bd59(0x374af78ad1881948706466aba5b859915ef255d7f18343989afb97cbfc8a93c0); /* assertPre */ 
c_0xb095bd59(0xd895a183ad7a53bc3e682fa8f32690147db145770620fb207e292e742e96b6a1); /* statement */ 
require(
                transferInfo.receiver.send(amountToSend),
                "Fail sending Ethers"
            );c_0xb095bd59(0xe1c2b3fef1854003c57222f1402cc900a69f6c868169b2b683287ce2b929e7a9); /* assertPost */ 

        } else {c_0xb095bd59(0x390124d2494ad746cd91531ada0dd275d09d0be0c978aa35cf8971f722782021); /* branch */ 

c_0xb095bd59(0xdae8c2a9fbe24b7bf7ade41bd6cf86e5d1077a66fcce117cd9622b0bb852d921); /* line */ 
            c_0xb095bd59(0xec664b22e85f1362507c2b6f7cc16613ae09c03698ec080a843da4e01e267c8b); /* statement */ 
uint256 amountToSend = transferInfo.amount.sub(
                transferInfo.amount.mul(fee).div(100)
            );
c_0xb095bd59(0x4accb0751917c2d7f0e95248bec540988ecae6235e509dfce2a1bc11b1ca197a); /* line */ 
            c_0xb095bd59(0xf59a08ca96a50393d23d865e7bfce337508327d1d591c3d449cf8b4d8eabe7cf); /* statement */ 
EdgewareToken assetContract = EdgewareToken(transferInfo.asset);
c_0xb095bd59(0xa7179ec84463e65f665ae8616d28f37dd8f88aede77a851f87659a87aeb7421a); /* line */ 
            c_0xb095bd59(0xc58d38c1a6ec23ad126c2eecaa0900441a70c90c8c4a4588fe0833ba44aaa9ba); /* assertPre */ 
c_0xb095bd59(0xff3cd0f4397ffcb724da2dd2972ccf6d5094ccb5e98bc32fec62e1a30f0d2a4a); /* statement */ 
require(
                assetContract.mintFor(transferInfo.receiver, amountToSend),
                "Error while mint tokens for the receiver"
            );c_0xb095bd59(0xf99c8fe2f25bed7caf6d9408ba10c0197b1c9005ea0063d0d8149baaf2646e82); /* assertPost */ 

        }
c_0xb095bd59(0xfb190ef490f2737f71e86470db1b5f462185dc33cabebc96887cdd861abd3935); /* line */ 
        c_0xb095bd59(0x9acd904f0d4a25b1b36d2b0b91ace9208a216ff28b6de3d040203b1a1889370e); /* statement */ 
return true;
    }
}
