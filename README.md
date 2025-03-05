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

We realize that single factor defense might attract potential adversaries. Therefore the system is designed with defense in depth in mind. For deposit, we relies both on the ICP's Bitcoin integration to sign off `chain tip`, and on the `CheckPoint` mechanism. For redemption, 2 of 3 multi-sig also provides fault-tolerance. See related sections for more details.

### Security over UX

zkBTC is designed to be fully decentralized, so there is no central role to operate the risk parameters. We have to assume worst case and defend zkBTC against such. Therefore the UX has to yield in case there is a conflict. For example, we require each Bitcoin deposit transaction to have a confirmation depth of at least 9, instead of 6. Throughout this document there are many more such examples.

## Audit Reports


## Securing Deposits


### Defense in Depth

* `DepositTxCircuit.SigVerif` checks if the `chain tip` (the latest block hash) is signed by an `DFinity` canister. This is the initial implementation of our long-term security design of decentralized roles signing off the `chain tip`.
* `Transaction Depth` check demands that each deposit transaction has certain confirmatioin depth. Note that the commonly recommended depth of `6` is based on on-chain verification, while in our system it is essentially an off-chain verification. Therefore we require at least `9` for small amount deposits, and even deeper for large amount deposits.
* `CheckPoint Depth` check demands that the enclosing block for each transaction is one of the decendents of certain recognized `CheckPoint` (also a Bitcoin block hash).

`CheckPoint` is maintained by the Ethereum smart contract without human intervention. The hash of the enclosing block for a **deep** enough trasaction could be a candidate for a new `CheckPoint`. When it is time to rotate check points, a random candidate is selected by the smart contract. Our security really does *not* depending on how random the selection process is. Rather, we impose a depth requirement for each of the candidate such that the adversary won't be able to reach without failing the checkpoint depth test. Our security architecture weights checkpoing safety more than individual blocks or transactions.

Now assuming some very powerful attacker commanding lots of hashing power has already cracked the first defense, the decentralized roles to sign off the chain tip. It still has to manage enough check point depth. The attacker won't be able to meet the `CheckPoint Depth` requirements, if we set proper checking rules in the smart contract. Before we proceed to discuss any specific rules, we must point out the obvious, that is, it is impossible to pass all legit blocks without also passing some offending blocks. Our aim here is not to reject all offending blocks but to make it as computation intensive as possible for adversaries.

Suppose the attacker has 10% of all honest hashing power combined, on average it has to spend at least 900 minutes (15 hours) to meet the transaction depth requirement for a small amount deposit. Meanwhile, there have been around 90 new blocks mined in the Bitcoin mainnet. The attacker would found out checkpoint depth deficit to be 81. If the attacker has 30% of all hasing power, numbers become 300 minutes, 30 new blocks and 21 blocks of checkpoint depth deficit. 

The smart contract, however, needs to take care of block timestamp drift, proof generation time, block interval variance, time to broadcast and include the smart contract invocation transaction, etc. For example, the timestamp of any Bitcoin block might be as early as just a bit later than the median value of its past 11 blocks. That will generate 1 hour or about 6 blocks more than the actual depth. The smart contract will have to substract 6 or more from its estimated depth, so that a *legit deposit won't be declined*. We could leave some more time for various other factors, ranging from half to one hour. Thus:
```
    required_minimal_depth = estimated_depth - allowance
    9 <= allowance <=12
```

Now let's talk about how to estimate the checkpoint depth. In case the transaction is even deeper than the checkpoint, or just rests in the checkpoint block, we simply return true as checkpoint is trusted by the smart contract. Otherwise, our first attempt is: 
```Solidity
    estimated_depth = (eth_block.timestamp - tx_block.timestamp) / 600 + (cp_depth - tx_depth);
```

We assume the Ethereum timestamp as obtained by `block.timestamp` is very close to real time ([ref](https://ethereum.stackexchange.com/questions/5927/how-would-a-miner-cope-with-a-huge-block-time)). However, since the Bitcoin transaction and its enclosing block could be generated by the attacker, its timestamp could not be trusted. We could instead compute the average block interval first, as:
```Solidity
    average_interval = (eth_block.timestamp - cp_block.timestamp) / cp_depth; // in seconds
    estimated_depth = average_interval * tx_depth / 600 + (cp_depth - tx_depth);
```

On the other hand, the timestamp of the checkpoint Bitcoin block could be at most 2 hours in the future. This will render the above estimation smaller than the actual value and generate some *free* depth. The smart contract maintain a minimal checkpoint depth of 72, therefore the attackers could only utilize a small portion of this *free* depth. Let's say one mighty attacker correctly guessed the next checkpoint and manage to mine minimal blocks such that the checkpoint is chosen with depth of 72. That is, `cp_depth` is 72 and `tx_depth` is 9. We shall have:
```
    saved_interval = 7200 / 72 = 100; // seconds
    free_depth = 100 * 9 / 600 = 1.5;
```

If the attacker has much more hashing power, say 30%, then then *free* depth is close to 4, or 6 for 50%. As long as attacker's depth deficit is larger than 6 after counting in the `allowance`, we are safe.

How much hashing power (x%) must the attacker control in order to have a deficit within 6?
```golang
    average_time_for_9_blocks := 9 * average_interval / (x/100)
    expected_average_blocks_mainnet := average_time_for_9_blocks / average_interval = 900 / x
    deficit := expected_average_blocks_mainnet - 9
```
Solve `x` for `deficit <= 6 + allowance`:
```
    cp_depth >= required_minimal_depth --> cp_depth >= average_interval * tx_depth / 600 + (cp_depth - tx_depth) - allowance
                                       --> allowance >= (average_interval / 600 - 1) * tx_depth
    deficit <= 6 + allowance --> 900 / x <= 15 + allowance --> x >= 900 / (15 + allowance)
```
If `average_interval` is y% higher than the target (600 seconds or 10 minutes), `allowance` must be at least y% of `tx_depth`. Or a legit transaction might be declined. We can set y to 10 as it seems most of time y is within 10 (TODO more data analysis). Since most of the time `tx_depth` is 9 or just a little bit bigger, this translates to 1, or 2 if y is 20. This justifies the decision to set the total allowance to some value between 9 and 12, counting in various factors mentioned earlier.

Set `allowance` to 9 and continue:
```
    900 / x <= 15 + allowance --> x >= 900 / (15 + allowance) = 37.5 (percentage)
```
Or `x >= 33.3%` for `allowance = 12`. Now a rational attacker won't spend such hashing power to manage a small amount deposit. The only loophole here is for attacker to stuff many *fake* small amount deposits in one block, and hope to win them all. On that consideration, our smart contract will raise the `tx_depth` requirement to defeat such attempts.

For large amount of deposit, we might require `tx_depth` to be at least 15 instead of 9. Attacker's deficit will be `deficit = (100/x - 1)*15`. Set `allowance` to 10 (having more blocks calls for more allowance), and we have:
```
    (100/x - 1)*15 <= 6 + 10 --> x >= 48.3 (percentage)
```

For even larger amount, we could furhter require `tx_depth` to be at least 24. Set `allowance` to 12, and we have:
```
    (100/x - 1)*24 <= 6 + 12 --> x >= 57.1 (percentage)
```

Note that we were talking about average case. There are small chances that the attacker mines more blocks sooner than average. We leave the further analysis to a later release. Setting 24 (57.1%) instead of 18 (50%) is also a pre-emptive step. TODO

The `tx_depth` requirement for a checkpoint candidate is set to 36 (with `allowance` set to 15):
```
    (100/x - 1)*36 <= 6 + 15 --> x >= 63.1 (percentage)
```

## Securing Redemption


### opZKP


### MultiSig Design


### ICP tECDSA Security


### SGX and Oasis


## chainark


## System Upgradability


## Open Source Plan