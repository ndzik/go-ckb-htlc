package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

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

var bobPubKey = "0x0383abf94e8d2d8f5309cda378dd3d46ae70293318c32b6b7065f6c0fedcf110af"
var bobSecpArg = "06f64f73b0917b45a1544168ad66ecc2805b13a4"
var bobPrivkey = "8817ec90e89553dad26d18e76ef70855ccecb970d784814eb13102e8e947f5ae"
var fromAddress = "ckt1qyqqdaj0wwcfz769592yz69dvmkv9qzmzwjq0xefx2"
var toAddress = "ckt1qyqqdaj0wwcfz769592yz69dvmkv9qzmzwjq0xefx2"
var secretmessage = "secret message"
var invalidmessage = "invalid message"
var htlcContract = "htlc-debug"

func main() {
	client, err := rpc.Dial("http://127.0.0.1:8114")
	if err != nil {
		log.Fatalf("dialing rpc error: %v", err)
	}

	codeHash, htlcTxHash, err := deployHTLCAt(client)
	if err != nil {
		log.Fatalf("deploying htlc-contract: %v", err)
	}
	fmt.Printf("CODE_HASH: %s\n", codeHash.String())
	fmt.Printf("HTLC-TX-HASH: %s\n", htlcTxHash.String())

	time.Sleep(time.Second * 6)

	hashedSecret32 := blake2b.CkbSum256([]byte(secretmessage))
	argsb := htlc.NewHtlcArgsBuilder()
	hashedSecret20, err := htlc.Byte20FromSlice(hashedSecret32[:20], false)
	if err != nil {
		log.Fatalf("serializing hased secret: %v\n", err)
	}
	argsb = argsb.HashedSecret(*hashedSecret20)
	args := argsb.Build()
	htlcScript := &types.Script{
		CodeHash: codeHash,
		HashType: types.HashTypeData,
		Args:     args.AsSlice(),
	}
	scriptHash, err := htlcScript.Hash()
	if err != nil {
		log.Fatalf("generating htlcScript hash: %v", err)
	}
	fmt.Printf("SCRIPT-HASH: %s\n", scriptHash.String())
	lockTxHash, err := lockPayment(client, 420, htlcScript)
	if err != nil {
		log.Fatalf("locking payment with htlc-contract: %v", err)
	}
	fmt.Printf("LOCK-TX-HASH: %s\n", lockTxHash.String())

	time.Sleep(time.Second * 6)

	unlockTxHash, err := unlockLockTO(client, *htlcTxHash, *lockTxHash)
	if err != nil {
		log.Printf("unlocking transaction: %v", err)
	} else {
		fmt.Printf("UNLOCK-TX-HASH: %s\n", unlockTxHash.String())
	}

	time.Sleep(time.Second * 46)

	unlockTxHash, err = unlockLockTO(client, *htlcTxHash, *lockTxHash)
	if err != nil {
		log.Printf("unlocking transaction: %v", err)
	} else {
		fmt.Printf("SECOND UNLOCK-TX-HASH: %s\n", unlockTxHash.String())
	}
}

func deployHTLCAt(client rpc.Client) (types.Hash, *types.Hash, error) {
	pay, err := payment.NewPayment(fromAddress, toAddress, bytesToShannon(200500), 200800)
	if err != nil {
		return types.Hash{}, nil, err
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return types.Hash{}, nil, err
	}

	data, err := ioutil.ReadFile(htlcContract)
	if err != nil {
		return types.Hash{}, nil, err
	}

	tx.OutputsData[0] = data

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return types.Hash{}, nil, err
	}

	_, err = pay.Sign(key)
	if err != nil {
		return types.Hash{}, nil, errors.WithMessage(err, "unable to sign htlc-contract tx")
	}

	htlcTxHash, err := pay.Send(client)
	if err != nil {
		return types.Hash{}, nil, errors.WithMessage(err, "unable to deploy htlc-contract")
	}

	return blake2b.CkbSum256(data), htlcTxHash, nil
}

func lockPayment(client rpc.Client, amount int64, script *types.Script) (*types.Hash, error) {
	pay, err := payment.NewPayment(fromAddress, toAddress, bytesToShannon(amount), 10000)
	if err != nil {
		return nil, errors.WithMessage(err, "creating payment")
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return nil, errors.WithMessage(err, "generating locking TX")
	}

	// set output lockscript to htlc-contract
	tx.Outputs[0].Lock = script

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return nil, errors.WithMessage(err, "creating secp-key")
	}

	_, err = pay.Sign(key)
	if err != nil {
		return nil, errors.WithMessage(err, "signing locking TX")
	}

	lockedTxHash, err := pay.Send(client)
	if err != nil {
		return nil, errors.WithMessage(err, "sending locking TX")
	}

	return lockedTxHash, nil
}

func unlockLockTO(client rpc.Client, htlcTxHash, lockTxHash types.Hash) (*types.Hash, error) {
	systemScripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to load systemscripts")
	}

	scriptArg, err := hex.DecodeString(bobSecpArg)
	if err != nil {
		return nil, errors.WithMessage(err, "decoding secparg")
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

	secpScript := types.Script{
		CodeHash: systemScripts.SecpSingleSigCell.CellHash,
		HashType: types.HashTypeType,
		Args:     scriptArg,
	}

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: bytesToShannon(419),
		Lock:     &secpScript,
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
		return nil, errors.WithMessage(err, "adding inputs for transaction")
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
	for _, c := range invalidmessage {
		bb = bb.Push(htlc.NewByte(byte(c)))
	}
	bint := htlc.NewUint32Builder()
	bint.Set([4]htlc.Byte{{0x0}, {0x0}, {0x0}, {0x0}})
	wab := htlc.NewHtlcWitnessBuilder()
	wab = wab.Secret(bb.Build())
	wab = wab.Blockheader(bint.Build())
	htlcWitness := wab.Build()

	tipHeader, err := client.GetTipHeader(context.Background())
	if err != nil {
		return nil, errors.WithMessage(err, "getting tip header")
	}
	txX, err := client.GetTransaction(context.Background(), lockTxHash)
	if err != nil {
		return nil, errors.WithMessage(err, "fetching TX status")
	}

	lockBlockHash := *txX.TxStatus.BlockHash
	fmt.Printf("Blockhash of LOCK-TX: %#x\n", lockBlockHash.Bytes())
	fmt.Printf("Blockhash of TipHeader: %#x\n", tipHeader.Hash.Bytes())
	tx.HeaderDeps = append(tx.HeaderDeps, tipHeader.Hash, lockBlockHash)

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return nil, errors.WithMessage(err, "hex to key")
	}
	err = transaction.SingleSignTransaction(tx, group, witnessargs, key)
	if err != nil {
		return nil, errors.WithMessage(err, "signing transaction")
	}
	tx.Witnesses[0] = htlcWitness.AsSlice()

	txSer, err := tx.Serialize()
	if err != nil {
		return nil, errors.WithMessage(err, "serializing transaction")
	}
	ioutil.WriteFile("dumpedTX", txSer, os.ModeAppend)

	txHash, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		return nil, errors.WithMessage(err, "sending transaction")
	}

	return txHash, nil
}

func unlockLockSecret(client rpc.Client, htlcTxHash, lockTxHash types.Hash) (*types.Hash, error) {
	systemScripts, err := utils.NewSystemScripts(client)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to load systemscripts")
	}

	scriptArg, err := hex.DecodeString(bobSecpArg)
	if err != nil {
		return nil, errors.WithMessage(err, "decoding secparg")
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

	secpScript := types.Script{
		CodeHash: systemScripts.SecpSingleSigCell.CellHash,
		HashType: types.HashTypeType,
		Args:     scriptArg,
	}

	tx.Outputs = append(tx.Outputs, &types.CellOutput{
		Capacity: bytesToShannon(419),
		Lock:     &secpScript,
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
		return nil, errors.WithMessage(err, "adding inputs for transaction")
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
	for _, c := range secretmessage {
		bb = bb.Push(htlc.NewByte(byte(c)))
	}
	wab := htlc.NewHtlcWitnessBuilder()
	wab = wab.Secret(bb.Build())
	htlcWitness := wab.Build()

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return nil, errors.WithMessage(err, "hex to key")
	}

	err = transaction.SingleSignTransaction(tx, group, witnessargs, key)
	if err != nil {
		return nil, errors.WithMessage(err, "signing transaction")
	}

	tx.Witnesses[0] = htlcWitness.AsSlice()

	txhash, err := client.SendTransaction(context.Background(), tx)
	if err != nil {
		return nil, errors.WithMessage(err, "sending transaction")
	}

	return txhash, nil
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
