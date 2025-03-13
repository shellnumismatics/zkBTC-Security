# zkBTC Security

This is the security document for the [zkBTC decentralized bridge](https://zkbtc.money), developed by [Lightec Labs](https://lightec.xyz). Follow us on [X](https://x.com/LightecXYZ).

## Product Summary

zkBTC is a ZKP-based bridge to securely bridge Bitcoin to Ethereum, and then all other major L1s and L2s. The basic workflow are:

* Deposit - user sends some $BTC to a designated operator address. Such a transaction is proved and the proof is verified in an Ethereum smart contract. After successful verification, the smart contract mints $zkBTC tokens, and transfers these tokens to the address supplied along with the deposit (in a `OP_RETURN` output).
* Use - users can use $zkBTC tokens any way they wish for, and the $zkBTC tokens are equivalent to $BTC in the Ethereum ecosystem.
* Redemption - user calls an Ethereum smart contract function to burn some $zkBTC tokens. The function will also leave some transaction logs specifying which available UTXOs to be spent. 

For more information and general use, please checkout our [Gitbook](https://lightec.gitbook.io/lightecxyz).

We design zkBTC to be fully decentralized, without any central role to operate on the users' assets. To achieve such an ambitious goal, we proposed to add an `OP_ZKP` opcode to Bitcoin so that Bitcoin can verify zero-knowledge proof as spending conditions of UTXOs. This way thers is no private keys to be managed at all for the `Redepmtion`. To redeem back to Bitcoin, one just need to submit a proof meeting certain critterias. Finding a ZKP scheme for `OP_ZKP` is proven extremely difficult, yet we do have a draft [here](https://github.com/opzkp/tea-horse).

Before `OP_ZKP` could be realized, we also have an alternative solution, that is to have multiple safe platforms to manage private keys such that:

* each platform is designed to safekeep the private key in a way that it is nearly impossible to learn the content of the private key;
* each platform only signs the redemption transaction after a successful ZKP verificatioin;
* we can tolerate one of the platforms to be craked or failed without losing security or losing assets.

Please turn to later sections for more details.

## Security Architecture


### Fully On-Chain

Recent security incidents reminded us to keep the frontend safe as well. We are going to deploy the frontend on-chain as well.

### Circuit Cascading

In both directions, there are many circuits working together. Different circuits are combined together via verification key fingerprint binding. The basic idea is to compute a `FingerPrint` for the verifying key of a circuit, as the identifying value. The `FingerPrint` is computed as the `MiMc` hash of the key components of the in-circuit verifying key. The [codes](https://github.com/lightec-xyz/common/blob/master/utils/fingerprint.go) could be found in the [common component](https://github.com/lightec-xyz/common/tree/master), and is excerpted below:

```golang
// FingerPrint() returns the MiMc hash of the VerifyingKey. It could be used to identify a VerifyingKey
// during recursive verification.
func InCircuitFingerPrint[FR emulated.FieldParams, G1El algebra.G1ElementT, G2El algebra.G2ElementT](
	api frontend.API, vk *plonk.VerifyingKey[FR, G1El, G2El]) (frontend.Variable, error) {
	var ret frontend.Variable
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return ret, err
	}

	mimc.Write(vk.BaseVerifyingKey.NbPublicVariables)
	mimc.Write(vk.CircuitVerifyingKey.Size)
	mimc.Write(vk.CircuitVerifyingKey.Generator.Limbs[:]...)

	comms := make([]kzg.Commitment[G1El], 0)
	comms = append(comms, vk.CircuitVerifyingKey.S[:]...)
	comms = append(comms, vk.CircuitVerifyingKey.Ql)
	comms = append(comms, vk.CircuitVerifyingKey.Qr)
	comms = append(comms, vk.CircuitVerifyingKey.Qm)
	comms = append(comms, vk.CircuitVerifyingKey.Qo)
	comms = append(comms, vk.CircuitVerifyingKey.Qk)
	comms = append(comms, vk.CircuitVerifyingKey.Qcp[:]...)

	for _, comm := range comms {
		el := comm.G1El
		switch r := any(&el).(type) {
		case *sw_bls12377.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bls12381.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bls24315.G1Affine:
			mimc.Write(r.X)
			mimc.Write(r.Y)
		case *sw_bw6761.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		case *sw_bn254.G1Affine:
			mimc.Write(r.X.Limbs[:]...)
			mimc.Write(r.Y.Limbs[:]...)
		default:
			return ret, fmt.Errorf("unknown parametric type")
		}
	}

	mimc.Write(vk.CircuitVerifyingKey.CommitmentConstraintIndexes[:]...)

	result := mimc.Sum()

	return result, nil
}
```

### Defense in Depth

We realize that single factor defense might attract potential adversaries. Therefore the system is designed with defense in depth in mind. For deposit, we rely both on the ICP's Bitcoin integration to sign off `chain tip`, and on the `CheckPoint` mechanism. For redemption, 2 of 3 multi-sig also provides fault-tolerance. See related sections for more details.

### Security over UX

zkBTC is designed to be fully decentralized, so there is no central role to operate the risk parameters. We have to assume worst case and defend zkBTC against such. Therefore the UX has to yield in case there is a conflict. For example, we require each Bitcoin deposit transaction to have a confirmation depth of at least 9, instead of 6. Throughout this document there are many more such examples.

## Audit Reports


## Securing Deposits


### Defense in Depth - Overall Design

We have designed three defenses against potential attacks, layered in depth:

* `DepositTxCircuit.SigVerif` checks if the `chain tip` (the latest block hash) is signed by an `DFinity` canister. This is the initial implementation of our long-term security design of decentralized roles signing off the `chain tip`.
* `Transaction Depth` check demands that each deposit transaction has certain confirmatioin depth. Note that the commonly recommended depth of `6` is based on on-chain verification, while in our system it is essentially an off-chain verification. Therefore we require at least `9` for small amount deposits, and even deeper for large amount deposits.
* `CheckPoint Depth` check demands that the enclosing block for each transaction is one of the decendents of certain recognized `CheckPoint` (also a Bitcoin block hash).

Now assuming some very powerful attacker commanding lots of hashing power has already cracked the first defense, the decentralized roles to sign off the chain tip. It still has to manage enough check point depth. The attacker won't be able to meet the both the `Transaction Depth` requirement and the `CheckPoint Depth` requirement, if we set proper checking rules in the smart contract. Before we proceed to discuss any specific rules, we must point out the obvious, that is, it is impossible to pass all legit blocks without also passing some offending blocks if the adversary indeeds masters too much hashing power. Our aim here is not to reject all offending blocks but to make it as computation intensive as possible for adversaries, such that attacking us is not economically desirable.

### CheckPoint

#### Estimating CheckPoint Depth

The smart contract must estimate the checkpoint depth on its own so that it could check if the value presented in the proof is acceptable or not. 

In case the transaction is even deeper than the checkpoint, or just rests in the checkpoint block, we simply return true for checkpoint depth checking as checkpoint is trusted by the smart contract. Otherwise, our first attempt is: 
```Solidity
    estimated_depth = (eth_block.timestamp - tx_block.timestamp) / 600 + (cp_depth - tx_depth);
```

We assume the Ethereum timestamp as obtained by `block.timestamp` is very close to real time as of the contract execution ([ref](https://ethereum.stackexchange.com/questions/5927/how-would-a-miner-cope-with-a-huge-block-time)). However, since the Bitcoin transaction and its enclosing block could be generated by the adversary, its timestamp could not be trusted. As `cp_depth` could also be derived from the adversary's fork chain, it is also not reliable. 
```Solidity
    estimated_depth = (eth_block.timestamp - cp_block.timestamp) / 600;
```

Alternatively we could compute the average interval between checkpoint and 'now', then to estimate the depth. However, this computation requires unreliable `cp_depth`.

We assume a 10-minutes average block interval here. This is often *not* the actual case. A variation of 10% is rather common. This is handled with allowance. See next sections.

What if the proof submission is purposefully delayed such that `eth_block.timestamp` is much later than it should have been? In that case, the `estimated_depth` would be larger than the actual value. This does the adversary no good. For the same reason, if the submission is dealyed for too long, a valid deposit might be declined. Fortunately in our proving-as-mining incentive setting, this will not happen a lot. Every miner will do their best to submit proof asap to earn proving rewards.

#### Checking CheckPoint Depth

Suppose the attacker has 10% of all honest hashing power combined, on average it has to spend at least 900 minutes (15 hours) to meet the transaction depth requirement for a small amount deposit, which requires `tx_depth` to be at least 9. Meanwhile, there have been around 90 new blocks mined in the Bitcoin mainnet. The attacker would found out checkpoint depth deficit to be 81. If the attacker has 30% of all hasing power, numbers become 300 minutes, 30 new blocks and 21 blocks of checkpoint depth deficit. 

The smart contract, however, needs to take care of block timestamp drift, proof generation time, block interval variance, time to broadcast and include the smart contract invocation transaction, etc. For example, the timestamp of any Bitcoin block might be as early as just a bit later than the median value of its past 11 blocks. That will generate 1 hour or about 6 blocks more than the actual depth since we use `eth_block.timestamp` to estimate the checkpoint depth. The smart contract will have to substract 6 or more from its estimated depth, so that a *legit* deposit won't be declined. We could leave some more time for various other factors, ranging from half to one hour. Thus:
```
    required_minimal_depth = estimated_depth - allowance
```

#### Setting a Proper Allowance

Specifically, we'd like to reserve 6 for the potential checkpoint timestamp error, 2 for waiting for the chain tip to be available and and proof to be generated, and then 1 for every additional 6 confirmation depth requirement covering the variation of hashing power and block time.
```
    allowance = 6 + 2 + (depth - 6)/6 = 7 + depth/6
```

Therefore for transaction confirmation depth requirements of 9, 12, 18, 24 and the checkpoint candidate depth requirement of 36, the corresponding allowance is 9, 9, 10, 11, and 13.

#### Becoming a CheckPoint Candidate

`CheckPoint` is maintained by the Ethereum smart contract without human intervention. The hash of the enclosing block for a **deep** enough trasaction could be a candidate for a new `CheckPoint`. When it is time to rotate check points, a random candidate is selected by the smart contract. Our security really does *not* depend on how random the selection process is. Rather, we impose a depth requirement for each of the candidate such that the adversary won't be able to reach without failing the checkpoint depth test. Our security architecture weights checkpoing safety more than individual blocks or transactions. And note that the formula of `estimated_depth` already assumes that adversary starts to mine its own blocks based on a would-be checkpoint block when it is freshly mined. A successful guessing of next checkpoint grants no additional advantages to adversaries.

Besides the depth requirement for checkpoint candidate, we also check if the timestamp of the checkpoint block is not too far in its past or future. The timestamp of the checkpoint block could be at most 2 hours in its future according to the Bitcoin consensus rules, resulting in some *free* depth to adversaries. To prevent this free depth from becoming too many, we run some checks in the circuit and prove a flag, which could be checked by the smart contract. On the other hand, if the checkpoint timestamp is in its past, legit deposit might be declined. So the circuit also checks this case and set a flag accordingly.

What if the in-circuit check is not reliable enough (for example, the blocks we use to check the timestamp are ALL in their future), and the checkpoint candidate still carry a timestamp in its past or future too far away? 

Althoug we believe the in-circuit check is a strong defense, under the principle of *Defense in Depth* we could still discuss this hypothetical case. Since the `estimated_depth` is based on the `average_interval` between checkpoint and `now`, the free depth gets averaged, propotional to the rate of `tx_depth` and `cp_depth`:
```Solidity
    estimated_depth = (eth_block.timestamp - (cp_block.true_timestamp + 7200)) / 600
                    = better_estimation - free_depth;
    free_depth      = 12;
```

Note that `better_estimation` is unknown to the smart contract, and is used here simply for clarification of this text.

#### Putting Everything Together

We need to find out the threshold of hashing power that an adversary must command in order to defeat our checkpoint system. Given:
```Solidity
    estimated_depth = (eth_block.timestamp - (cp_block.true_timestamp + 7200)) / 600
                    = better_estimation - free_depth;
    free_depth      = 12;
    required_minimal_depth = estimated_depth - allowance;
    allowance = 7 + depth/6
```

Suppose the transaction depth requirement is D (D = 9 for small amount deposit, 12 for medium amount, 18 and 24 for even larger amounts), and the attacker commands x% hashing power as compared to all honest miners combined. At some point on or after the checkpoint block, the attacker must begin to mine its own blocks. In order to meet the transaction depth requirement, the attacker must spend `average_attacker_time_for_D_blocks` on average, assuming the average block interval to be 10 minutes:
```golang
    average_attacker_time_for_D_blocks := D * 600 / (x/100) = D * 60000/x
```

Meanwhile the mainnet keeps producing new blocks, the expected average blocks mined are:
```golang
    expected_average_blocks_mainnet := average_attacker_time_for_D_blocks / 600 = D * 100/x
```

During this period, the checkpoint depth that would be obtained by the attaker will lag behind that of mainnet by `cp_depth_diff`:
```golang
    cp_depth_diff := expected_average_blocks_mainnet - D = D * (100/x - 1)
```

The attacker needs `cp_depth_diff <= allowance`. But since there could be free depth, he actually needs only `cp_depth_diff <= allowance + free_depth` or:
```golang
    // D * (100/x - 1) <= allowance + free_depth <--> x >= 100*D/(allowance + D + 12)
    // (allowance + D + 12) must be positive
```

Solving the above inequalities for `(D, allowance) = (9, 9)`:
```golang
    // x >= 900/(9 + 9 + 12) = 30
```
And for `(D, allowance) = (12, 9), (18, 10), (24, 11)`
```golang
    // x >= 1200/( 9 + 12 + 12) = 36.4
    // x >= 1800/(11 + 18 + 12) = 43.9
    // x >= 2400/(12 + 24 + 12) = 50.0
```

Note that we were talking about average case. There are small chances that the attacker mines more blocks sooner than average. But the block time variation has been handled with the allowance value (see earlier sections).

The `tx_depth` requirement for a checkpoint candidate is set to 36 (with `allowance` set to 13):
```golang
    // x >= 3600/(13 + 36 + 12) = 59.0
```

#### Escalating the Depth Requirement

It seems not profitable to spend at least 30% of all total-net hashing power just to make a fake deposit of a small amount. The attacker, however, no double will try to stuff as many transactions as possible into one block and hope to deposit all of them successfully.

To counter this measure, we keep the count of deposit transactions per block, and escalate the depth requirement once certain limit is reached.

#### An Even Aggresive Attacker

In the above discussion, we assume the attacker use *new* hashing power instead of drawing the *existing* mining power to compute the attack. This way, the mainnet is generating new blocks in a relatively steady rate. However, if a very powerful attacker can turn some existing hashing power to attack zkBTC, then the rate mainnet is producing new blocks will be slowed down. And our analysis is impacted. This is the typical `p vs q` situation in the original [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf).

Nonetheless, our security architecture really does not rely on the actual block interval. We use the expected 10 minute and then `allowance` to handle any variation. So if the supposed situation do happen, then instead of invalid deposits being accepted, valid deposits might get declined as the checkpoint depth requirement cannot be met, but only temporally.

To recover from this situation, the mainnet must have mined blocks faster than the 10 minutes expectation, to make up the 'lost depth'. This could happen a while after the attacker has stopped without gains, or more honest hashing power join the mining as their owners see the opportunity, or the difficulty adjustment results in a lower difficulty due to prolonged average block interval and hence faster block mining.

### Defense in Depth - Replacing Chain Tip Signature with More Depth Requirements

In the discussion so far, the signature to the chain tip has become the single point of failure (SPoF). That is, if for some reason the ICP canister cannot sign the tip block of Bitcoin, then we cannot generate a proof that is acceptable to the deployed smart contract. To overcome this hurdle, we could replace the signature with more depth requirements.

Our current practice is to double the depth requirements, and update the allowance value accordingly. This is on top of the depth requirement escalation mentioned earlier.

## Securing Redemption


### The Ethereum Light Client Protocol


### opZKP


### MultiSig Design


### ICP tECDSA Security


### SGX and Oasis


## chainark


## System Upgradability


## Open Source Plan