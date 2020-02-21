// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/flyinox/crypto/sm/sm2"
	sm "github.com/flyinox/crypto/sm/sm2"
)

const ecPrivKeyVersion = 1

// ecPrivateKey reflects an ASN.1 Elliptic Curve Private Key Structure.
// References:
//   RFC 5915
//   SEC1 - http://www.secg.org/sec1-v2.pdf
// Per RFC 5915 the NamedCurveOID is marked as ASN.1 OPTIONAL, however in
// most cases it is not.
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// ParseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
func ParseECPrivateKey(der []byte) (interface{}, error) {
	return parseECPrivateKey(nil, der)
}

// MarshalECPrivateKey marshals an EC private key into ASN.1, DER format.
func MarshalECPrivateKey(key interface{}) ([]byte, error) {
	var curve elliptic.Curve
	var x, y *big.Int
	var count int
	var bytes []byte

	switch key := key.(type) {
	case *ecdsa.PrivateKey:
		count = (key.Params().BitSize + 7) >> 3
		bytes = key.D.Bytes()
		curve = key.Curve
		x = key.X
		y = key.Y
		oid, ok := oidFromNamedCurve(curve)
		if !ok {
			return nil, errors.New("x509: unknown elliptic curve")
		}
		return asn1.Marshal(ecPrivateKey{
			Version:       1,
			PrivateKey:    PadBytes(bytes, count),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(curve, x, y)},
		})

	case *sm.PrivateKey:
		count = sm2.CurveSize(key.PublicKey.Curve)
		bytes = key.D.Bytes()
		curve = key.Curve
		x = key.X
		y = key.Y
		oid, ok := oidFromNamedCurve(curve)
		if !ok {
			return nil, errors.New("x509: unknown elliptic curve")
		}
		return asn1.Marshal(ecPrivateKey{
			Version:       1,
			PrivateKey:    PadBytes(bytes, count),
			NamedCurveOID: oid,
			PublicKey:     asn1.BitString{Bytes: key.PublicKey.Marshal()}, //elliptic.Marshal(curve, x, y)},
		})

	}
	return nil, errors.New("x509: unsupported elliptic curve algorithm")
}

// parseECPrivateKey parses an ASN.1 Elliptic Curve Private Key Structure.
// The OID for the named curve may be provided from another source (such as
// the PKCS8 container) - if it is provided then use this instead of the OID
// that may exist in the EC private key structure.
func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key interface{}, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		if namedCurveOID == nil {
			return nil, errors.New("ECPK: failed to parse EC private key: " + err.Error())
		}
	} else {
		if privKey.Version != ecPrivKeyVersion {
			return nil, fmt.Errorf("ECPK: unknown EC private key version %d", privKey.Version)
		}
	}
	kdata := privKey.PrivateKey
	if len(kdata) == 0 {
		kdata = der
	}
	k := new(big.Int).SetBytes(kdata)

	var curveOid *asn1.ObjectIdentifier
	if namedCurveOID != nil {
		curveOid = namedCurveOID
	} else {
		curveOid = &privKey.NamedCurveOID
	}
	curveECDSA := namedCurveFromOID(*curveOid)
	if curveECDSA != nil {

		curveOrder := curveECDSA.Params().N
		if k.Cmp(curveOrder) >= 0 {
			return nil, errors.New("ECPK: invalid elliptic curve private key value")
		}

		priv := new(ecdsa.PrivateKey)
		priv.Curve = curveECDSA
		priv.D = k

		privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

		// Some private keys have leading zero padding. This is invalid
		// according to [SEC1], but this code will ignore it.
		for len(privKey.PrivateKey) > len(privateKey) {
			if privKey.PrivateKey[0] != 0 {
				return nil, errors.New("ECPK: invalid private key length")
			}
			privKey.PrivateKey = privKey.PrivateKey[1:]
		}

		// Some private keys remove all leading zeros, this is also invalid
		// according to [SEC1] but since OpenSSL used to do this, we ignore
		// this too.
		copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
		priv.X, priv.Y = curveECDSA.ScalarBaseMult(privateKey)

		return priv, nil
	}

	// Non-ECDSA curve

	curve, err := sm.NewCurveByOID(curveOid)
	if err != nil {
		return nil, fmt.Errorf("ECPK: unknown elliptic curve %v", curveOid)
	}

	priv, err := sm.NewPrivateKey(curve, kdata)
	if err != nil {
		return nil, err
	}

	return priv, nil
}
