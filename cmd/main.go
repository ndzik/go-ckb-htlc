package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"

	"github.com/liushooter/blake2b"
	"github.com/pkg/errors"
	"github.com/ququzone/ckb-sdk-go/crypto/bech32"
	"github.com/ququzone/ckb-sdk-go/crypto/secp256k1"
	"github.com/ququzone/ckb-sdk-go/payment"
	"github.com/ququzone/ckb-sdk-go/rpc"
	"github.com/ququzone/ckb-sdk-go/transaction"
	"github.com/ququzone/ckb-sdk-go/types"
	"github.com/ququzone/ckb-sdk-go/utils"

	htlc "test/blockchain"
)

func genAddrFrom(pubKey []byte) string {
	ckbsum := blake2b.CkbSum256(pubKey)
	blake160 := ckbsum[:20]
	fmt.Printf("Blake2bPubHash: %#x\n", blake160)
	payload := []byte{0x01, 0x00}
	payload = append(payload, blake160...)
	cpayload, err := bech32.ConvertBits(payload, 8, 5, true)
	if err != nil {
		log.Fatalf("converting payload error: %v", err)
	}
	addr, err := bech32.Encode("ckt", cpayload)
	if err != nil {
		log.Fatalf("encoding cpayload error: %v", err)
	}

	return addr
}

var bobPubKey = "0x0383abf94e8d2d8f5309cda378dd3d46ae70293318c32b6b7065f6c0fedcf110af"
var bobSecpArg = "ed79d9b52a5936d9a871f0219824d833f7de3afe"
var bobPrivkey = "23b9dead7db56567fd3d38d0ef0764f7ec540e0b6ee5d3c0def0ee36e823aab0"
var bobAddr = "ckt1qyqw67wek549jdke4pclqgvcynvr8a778tlq6kg0sg"
var fromAddress = "ckt1qyqw67wek549jdke4pclqgvcynvr8a778tlq6kg0sg"
var toAddress = "ckt1qyqw67wek549jdke4pclqgvcynvr8a778tlq6kg0sg"
var secretmessage = "secret message"
var proposedSecret = "invalid message"
var htlcContract = "htlc-contract"

// 1 CKByte == 100.000.000 (1x10^8)
func bytesToShannon(ckb int64) uint64 {
	if ckb < 0 {
		return 0
	}
	bigckb := big.NewInt(ckb)
	base := big.NewInt(10)
	modulo := big.NewInt(0)
	bigckb.Mul(bigckb, base.Exp(base, big.NewInt(8), modulo))
	return bigckb.Uint64()
}

func deployHTLCAt(client rpc.Client) (types.Hash, error) {
	pay, err := payment.NewPayment(bobAddr, bobAddr, bytesToShannon(20000), 20000)
	if err != nil {
		return types.Hash{}, err
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return types.Hash{}, err
	}

	data, err := ioutil.ReadFile(htlcContract)
	if err != nil {
		return types.Hash{}, err
	}

	tx.OutputsData[0] = data

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return types.Hash{}, err
	}

	_, err = pay.Sign(key)
	if err != nil {
		return types.Hash{}, errors.WithMessage(err, "unable to sign htlc-contract tx")
	}

	//htlcTxHash, err := pay.Send(client)
	//if err != nil {
	//	return types.Hash{}, errors.WithMessage(err, "unable to deploy htlc-contract")
	//}
	//fmt.Printf("HTLC-CONTRACT-TX-HASH: %s\n", htlcTxHash.String())

	return blake2b.CkbSum256(data), nil
}

func lockPayment(client rpc.Client, amount int64, script *types.Script) error {
	pay, err := payment.NewPayment(bobAddr, bobAddr, bytesToShannon(amount), 10000)
	if err != nil {
		return errors.WithMessage(err, "creating payment")
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return errors.WithMessage(err, "generating locking TX")
	}

	// set output lockscript to htlc-contract
	tx.Outputs[0].Lock = script

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return errors.WithMessage(err, "creating secp-key")
	}

	_, err = pay.Sign(key)
	if err != nil {
		return errors.WithMessage(err, "signing locking TX")
	}

	lockedTxHash, err := pay.Send(client)
	if err != nil {
		return errors.WithMessage(err, "sending locking TX")
	}

	fmt.Printf("LOCK-TX-HASH: %s\n", lockedTxHash.String())
	return nil
}

func unlockLockTO(client rpc.Client, lockTX *types.Transaction) error {
	pay, err := payment.NewPayment(bobAddr, bobAddr, bytesToShannon(100), 1000)
	if err != nil {
		return errors.WithMessage(err, "creating payment")
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return errors.WithMessage(err, "creating TX")
	}

	cellDep := &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: types.HexToHash("0x343c4f92af9b9011f30316f9d2323ce304a0b0f025ed578a775f96cab073d2dc"),
			Index:  0,
		},
		DepType: types.DepTypeCode,
	}

	tx.CellDeps = append(tx.CellDeps, cellDep)

	return nil
}

func unlockLockSecret(client rpc.Client, htlcTxHash, lockTxHash types.Hash) error {
	systemScripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return errors.WithMessage(err, "unable to load systemscripts")
	}

	toAddress, err := hex.DecodeString(bobSecpArg)
	if err != nil {
		return errors.WithMessage(err, "decoding secparg")
	}

	tx := &types.Transaction{
		Version:    0,
		HeaderDeps: []types.Hash{},
		CellDeps: []*types.CellDep{
			{
				OutPoint: systemScripts.SecpSingleSigCell.OutPoint,
				DepType:  types.DepTypeDepGroup,
			},
		},
	}

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: bytesToShannon(419),
		Lock: &types.Script{
			CodeHash: systemScripts.SecpSingleSigCell.CellHash,
			HashType: types.HashTypeType,
			Args:     toAddress,
		},
	})
	tx.OutputsData = [][]byte{{}}

	group, witnessargs, err := transaction.AddInputsForTransaction(tx, []*types.Cell{
		{
			OutPoint: &types.OutPoint{
				TxHash: lockTxHash,
				Index:  0,
			},
		},
	})

	if err != nil {
		return errors.WithMessage(err, "adding inputs for transaction")
	}

	cellDep := &types.CellDep{
		OutPoint: &types.OutPoint{
			TxHash: htlcTxHash,
			Index:  0,
		},
		DepType: types.DepTypeCode,
	}
	tx.CellDeps = append(tx.CellDeps, cellDep)

	bb := htlc.NewBytesBuilder()
	for _, c := range proposedSecret {
		bb = bb.Push(htlc.NewByte(byte(c)))
	}
	wab := htlc.NewHtlcWitnessBuilder()
	wab = wab.Secret(bb.Build())
	htlcWitness := wab.Build()

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return errors.WithMessage(err, "hex to key")
	}
	err = transaction.SingleSignTransaction(tx, group, witnessargs, key)
	if err != nil {
		return errors.WithMessage(err, "signing transaction")
	}
	tx.Witnesses[0] = htlcWitness.AsSlice()

	txhash, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		return errors.WithMessage(err, "sending transaction")
	}

	fmt.Printf("tx hash htlc-unlock: %s\n", txhash.String())
	return nil
}

func main() {
	client, err := rpc.Dial("http://127.0.0.1:8114")
	if err != nil {
		log.Fatalf("dialing rpc error: %v", err)
	}

	//codeHash, err := deployHTLCAt(client)
	//fmt.Printf("CODE_HASH: %s\n", codeHash.String())
	//if err != nil {
	//	log.Fatalf("deploying htlc-contract: %v", err)
	//}

	//hashedSecret32 := blake2b.CkbSum256([]byte(secretmessage))
	//argsb := htlc.NewHtlcArgsBuilder()
	//hashedSecret20, err := htlc.Byte20FromSlice(hashedSecret32[:20], false)
	//argsb = argsb.HashedSecret(*hashedSecret20)
	//args := argsb.Build()
	//htlcScript := &types.Script{
	//	CodeHash: codeHash,
	//	HashType: types.HashTypeData,
	//	Args:     args.AsSlice(),
	//}
	//err = lockPayment(client, 420, htlcScript)
	//if err != nil {
	//	log.Fatalf("locking payment with htlc-contract: %v", err)
	//}

	htlcTxHash := types.HexToHash("0x5d1fed7599dd04aa02c90b83e718565fef27b835de170bf6ad30e6f58227bf5c")
	lockTxHash := types.HexToHash("0x01230e7923305cf8348716f12334b693d6bbbad097652f9166b1701e63ca20b9")
	err = unlockLockSecret(client, htlcTxHash, lockTxHash)
	if err != nil {
		log.Fatalf("unlocking transaction with secret: %v", err)
	}
}

func stdTX(client rpc.Client) error {
	// breaks on 6000000000
	// minimum occupied capacity of a secp256k1 cell is 61 bytes => 6.100.000.000 shannon == 61 CKByte
	// NewPayments() receives value in SHANNON
	pay, err := payment.NewPayment(fromAddress, toAddress, 6100000000, 10000)
	if err != nil {
		return errors.WithMessage(err, "create payment error: %v")
	}

	_, err = pay.GenerateTx(client)
	if err != nil {
		return errors.WithMessage(err, "generate transaction error: %v")
	}

	key, err := secp256k1.HexToKey(bobPrivkey)
	_, err = pay.Sign(key)
	if err != nil {
		return errors.WithMessage(err, "sign transaciton error: %v")
	}

	hash, err := pay.Send(client)
	if err != nil {
		return errors.WithMessage(err, "sending tx error: %v")
	}
	fmt.Println(hash)
	return nil
}
