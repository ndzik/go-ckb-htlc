package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

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

var bobSecpArg = "06f64f73b0917b45a1544168ad66ecc2805b13a4"
var bobPrivkey = "8817ec90e89553dad26d18e76ef70855ccecb970d784814eb13102e8e947f5ae"
var fromAddress = "ckt1qyqqdaj0wwcfz769592yz69dvmkv9qzmzwjq0xefx2"
var toAddress = "ckt1qyqqdaj0wwcfz769592yz69dvmkv9qzmzwjq0xefx2"
var secretmessage = "secret message"
var invalidmessage = "invalid message"
var htlcContract = "htlc-debug"

var logv, failv, ledgerv *gocui.View
var htlcTxHash, lockTxHash, codeHash *types.Hash

func main() {
	client, err := rpc.Dial("http://127.0.0.1:8114")
	if err != nil {
		log.Fatalf("dialing rpc error: %v", err)
	}

	g, err := gocui.NewGui(gocui.OutputNormal)
	if err != nil {
		log.Fatalf("creating terminal ui: %v", err)
	}
	defer g.Close()

	g.SetManagerFunc(layout)

	codeHash, htlcTxHash, err = deployHTLCAt(client)
	if err != nil {
		log.Fatalf("deploying htlc-contract: %v", err)
	}
	go g.Update(func(g *gocui.Gui) error {
		time.Sleep(time.Second * 1)
		v, err := g.View("Logv")
		if err != nil {
			log.Fatalf("getting logv printin meta: %v", err)
		}
		fmt.Fprintf(v, "CODEHASH: %v\n", codeHash.String())
		fmt.Fprintf(v, "HTLC-TX-HASH: %v\n", htlcTxHash.String())
		go watch(client, g, htlcTxHash)
		return nil
	})

	if err := g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit); err != nil {
		log.Panicln(err)
	}
	if err := g.SetKeybinding("", '1', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
		lockTxHash, err = lockPayment(client, 420, *codeHash)
		if err != nil {
			fmt.Fprintf(failv, "%#v\n", errors.WithMessage(err, "locking payment"))
			return nil
		}
		go watch(client, g, lockTxHash)
		fmt.Fprintf(logv, "LOCK-HASH: %v\n", lockTxHash.String())
		return nil
	}); err != nil {
		fmt.Fprintln(failv, err)
	}
	if err := g.SetKeybinding("", '2', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
		unlockTxHash, err := unlockLockSecret(client, *htlcTxHash, *lockTxHash)
		if err != nil {
			fmt.Fprintf(failv, "%#v\n", errors.WithMessage(err, "unlocking funds"))
			return nil
		}
		go watch(client, g, unlockTxHash)
		fmt.Fprintf(logv, "UNLOCK-TX-HASH: %v\n", unlockTxHash.String())
		return nil
	}); err != nil {
		fmt.Fprintln(failv, err)
	}
	if err := g.SetKeybinding("", '3', gocui.ModNone, func(*gocui.Gui, *gocui.View) error {
		unlockTxHash, err := unlockLockTO(client, *htlcTxHash, *lockTxHash)
		if err != nil {
			fmt.Fprintf(failv, "%#v\n", errors.WithMessage(err, "unlocking funds"))
			return nil
		}
		go watch(client, g, unlockTxHash)
		fmt.Fprintf(logv, "UNLOCK-TX-HASH: %v\n", unlockTxHash.String())
		return nil
	}); err != nil {
		fmt.Fprintln(failv, err)
	}
	if err := g.SetKeybinding("", 'k', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		scroll(ledgerv, -1)
		return nil
	}); err != nil {
		fmt.Fprintln(failv, err)
	}
	if err := g.SetKeybinding("", 'j', gocui.ModNone, func(g *gocui.Gui, v *gocui.View) error {
		scroll(ledgerv, 1)
		return nil
	}); err != nil {
		fmt.Fprintln(failv, err)
	}

	if err := g.MainLoop(); err != nil && err != gocui.ErrQuit {
		log.Panicln(err)
	}
}

func deployHTLCAt(client rpc.Client) (*types.Hash, *types.Hash, error) {
	pay, err := payment.NewPayment(fromAddress, toAddress, bytesToShannon(200500), 200900)
	if err != nil {
		return nil, nil, err
	}

	tx, err := pay.GenerateTx(client)
	if err != nil {
		return nil, nil, err
	}

	data, err := ioutil.ReadFile(htlcContract)
	if err != nil {
		return nil, nil, err
	}

	tx.OutputsData[0] = data

	key, err := secp256k1.HexToKey(bobPrivkey)
	if err != nil {
		return nil, nil, err
	}

	_, err = pay.Sign(key)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "unable to sign htlc-contract tx")
	}

	htlcTxHash, err := pay.Send(client)
	if err != nil {
		return nil, nil, errors.WithMessage(err, "unable to deploy htlc-contract")
	}

	dataHash := blake2b.CkbSum256(data)
	codeHash := types.Hash(dataHash)
	return &codeHash, htlcTxHash, nil
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
	fmt.Fprintf(logv, "SCRIPT-HASH: %s\n", scriptHash.String())
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

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func scroll(v *gocui.View, dy int) {
	_, y := v.Size()
	ox, oy := v.Origin()

	if oy+dy > strings.Count(v.ViewBuffer(), "\n")-y-1 {
		v.Autoscroll = true
	} else {
		v.Autoscroll = false
		v.SetOrigin(ox, oy+dy)
	}
}
func layout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("Logv", int(0.4*float32(maxX)), -1, maxX, int(0.5*float32(maxY+1))); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Autoscroll = true
		logv = v
	}
	if v, err := g.SetView("Failv", int(0.4*float32(maxX)), int(0.5*float32(maxY)), maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Autoscroll = true
		failv = v
	}
	if v, err := g.SetView("Ledger", -1, -1, int(0.4*float32(maxX)), maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Wrap = true
		v.Autoscroll = true
		ledgerv = v
	}
	return nil
}

func watch(client rpc.Client, g *gocui.Gui, txHash *types.Hash) {
	for {
		tx, err := client.GetTransaction(context.Background(), *txHash)
		if err != nil {
			fmt.Fprintln(failv, err)
		}
		b, err := json.MarshalIndent(tx, "", "\t")
		if err != nil {
			fmt.Fprintln(failv, err)
		}
		g.Update(func(g *gocui.Gui) error {
			ledgerv.Clear()
			v, err := g.View("Ledger")
			if err != nil {
				log.Fatalf("getting ledgerv: %v", err)
			}
			fmt.Fprintf(v, "%s\n", b)
			return nil
		})
		if tx.TxStatus.Status == "committed" {
			break
		}
		time.Sleep(time.Second * 1)
	}
}
