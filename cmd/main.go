package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"

	"github.com/jroimartin/gocui"
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

var bobSecpArg = "891d2fb5c93d7c4f73d36ee519e2e8cb7259e52f"
var bobPrivkey = "29ec7b9fd73fa9588b27686a1a4d7215dd4fa127681b912935b1df2ab42ab97b"
var fromAddress = "ckt1qyqgj8f0khyn6lz0w0fkaegeut5vkujeu5hs3rggyw"
var toAddress = "ckt1qyqgj8f0khyn6lz0w0fkaegeut5vkujeu5hs3rggyw"
var secretmessage = "secret message"
var invalidmessage = "invalid message"
var htlcContract = "htlc-debug"

var logv, failv *gocui.View
var htlcTxHash, lockTxHash *types.Hash

func main() {
	//client, err := rpc.Dial("http://127.0.0.1:8114")
	//if err != nil {
	//	log.Fatalf("dialing rpc error: %v", err)
	//}

	//codeHash, htlcTxHash, err := deployHTLCAt(client)
	//if err != nil {
	//	log.Fatalf("deploying htlc-contract: %v", err)
	//}
	//fmt.Printf("CODE_HASH: %s\n", codeHash.String())
	//fmt.Printf("HTLC-TX-HASH: %s\n", htlcTxHash.String())

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Fatalf("creating terminal ui: %v", err)
	}
	defer g.Close()

	g.SetManagerFunc(layout)

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	//if err := g.SetKeybinding("", '1', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
	//	lockHash, err := lockPayment(client, 420, codeHash)
	//	if err != nil {
	//		return errors.WithMessage(err, "locking payment")
	//	}
	//	fmt.Fprintf(logv, "LOCK-HASH: %v\n", lockHash.String())
	//	return nil
	//}); err != nil {
	//	fmt.Fprintln(failv, err)
	//}
	//if err := g.SetKeybinding("", '2', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
	//	unlockTxHash, err := unlockLockSecret(client, *htlcTxHash, *lockTxHash)
	//	if err != nil {
	//		return errors.WithMessage(err, "unlocking funds")
	//	}
	//	fmt.Fprintf(logv, "UNLOCK-TX-HASH: %v\n", unlockTxHash.String())
	//	return nil
	//}); err != nil {
	//	fmt.Fprintln(failv, err)
	//}
	//if err := g.SetKeybinding("", '3', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
	//	unlockTxHash, err := unlockLockTO(client, *htlcTxHash, *lockTxHash)
	//	if err != nil {
	//		return errors.WithMessage(err, "unlocking funds")
	//	}
	//	fmt.Fprintf(logv, "UNLOCK-TX-HASH: %v\n", unlockTxHash.String())
	//	return nil
	//}); err != nil {
	//	fmt.Fprintln(failv, err)
	//}

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if _, err := g.SetView("TXs", -1, -1, int(0.4*float32(maxX)), maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
	}
	if v, err := g.SetView("Logv", int(0.4*float32(maxX)), -1, maxX, int(0.5*float32(maxY+1))); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		logv = v
	}
	if v, err := g.SetView("Failv", int(0.4*float32(maxX)), int(0.5*float32(maxY)), maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		failv = v
	}
	return nil
}

//func run() {
//	codeHash, htlcTxHash, err := deployHTLCAt(client)
//	if err != nil {
//		log.Fatalf("deploying htlc-contract: %v", err)
//	}
//	fmt.Printf("CODE_HASH: %s\n", codeHash.String())
//	fmt.Printf("HTLC-TX-HASH: %s\n", htlcTxHash.String())
//
//	time.Sleep(time.Second * 6)
//	lockTxHash, err := lockPayment(client, 420, htlcScript)
//	if err != nil {
//		log.Fatalf("locking payment with htlc-contract: %v", err)
//	}
//	fmt.Printf("LOCK-TX-HASH: %s\n", lockTxHash.String())
//
//	time.Sleep(time.Second * 6)
//
//	unlockTxHash, err := unlockLockTO(client, *htlcTxHash, *lockTxHash)
//	if err != nil {
//		log.Printf("unlocking transaction: %v", err)
//	} else {
//		fmt.Printf("UNLOCK-TX-HASH: %s\n", unlockTxHash.String())
//	}
//
//	time.Sleep(time.Second * 46)
//
//	unlockTxHash, err = unlockLockTO(client, *htlcTxHash, *lockTxHash)
//	if err != nil {
//		log.Printf("unlocking transaction: %v", err)
//	} else {
//		fmt.Printf("SECOND UNLOCK-TX-HASH: %s\n", unlockTxHash.String())
//	}
//}

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

func htlcTypeScript(codeHash types.Hash) (*types.Script, error) {
	hashedSecret32 := blake2b.CkbSum256([]byte(secretmessage))
	argsb := htlc.NewHtlcArgsBuilder()
	hashedSecret20, err := htlc.Byte20FromSlice(hashedSecret32[:20], false)
	if err != nil {
		return nil, errors.WithMessage(err, "serializing hased secret")
	}
	argsb = argsb.HashedSecret(*hashedSecret20)
	args := argsb.Build()
	return &types.Script{
		CodeHash: codeHash,
		HashType: types.HashTypeData,
		Args:     args.AsSlice(),
	}, nil
}

func lockPayment(client rpc.Client, amount int64, codeHash types.Hash) (*types.Hash, error) {
	htlcScript, err := htlcTypeScript(codeHash)
	if err != nil {
		return nil, errors.WithMessage(err, "creating typescript")
	}
	scriptHash, err := htlcScript.Hash()
	if err != nil {
		log.Fatalf("generating htlcScript hash: %v", err)
	}
	fmt.Printf("SCRIPT-HASH: %s\n", scriptHash.String())
	pay, err := payment.NewPayment(fromAddress, toAddress, bytesToShannon(amount), 10000)
	if err != nil {
		return nil, errors.WithMessage(err, "creating payment")
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return nil, errors.WithMessage(err, "generating locking TX")
	}

	// set output lockscript to htlc-contract
	tx.Outputs[0].Lock = htlcScript

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
