// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/flyinox/crypto/sm/sm2"
	sm "github.com/flyinox/crypto/sm/sm2"
)

// pkcs8 reflects an ASN.1, PKCS#8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted, PKCS#8 private key.
// See RFC 5208.
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	switch {

	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeySM2):
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(privKey.Algo.Parameters.Bytes, namedCurveOID); err != nil {
			if _, err := asn1.Unmarshal(privKey.Algo.Parameters.FullBytes, namedCurveOID); err != nil {
				namedCurveOID = nil
			}
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to ASN.1 DER encoded form.
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	//var curvOID asn1.ObjectIdentifier
	var privKey []byte
	var keySize int
	switch key := key.(type) {

	case *rsa.PrivateKey:
		return MarshalPKCS1PrivateKey(key), nil

	case *ecdsa.PrivateKey:
		return MarshalECPrivateKey(key)

	case *sm.PrivateKey:
		privKey = key.D.Bytes()
		curvOID, _ := oidFromNamedCurve(key.Curve)
		keySize = int((key.Curve.Params().N.BitLen() + 7) / 8)
		padded := make([]byte, keySize)
		copy(padded[len(padded)-len(privKey):], privKey)
		//digestName, _ := sm2.Curve2Digest[key.Curve.Name]
		//digestOID, _ := sm2.Name2OID[digestName]
		//algoParams, err := asn1.Marshal([]asn1.ObjectIdentifier{curvOID, *digestOID})
		algoParams, err := asn1.Marshal([]asn1.ObjectIdentifier{curvOID})
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(pkcs8{
			Version: 0,
			Algo: pkix.AlgorithmIdentifier{
				Algorithm:  *sm2.Name2OID["id-GostR3410-2001"],
				Parameters: asn1.RawValue{Bytes: algoParams}, //asn1.RawValue{Bytes: algoParams},
			},
			PrivateKey: padded,
		})

	/*case *sm2.PrivateKey:
	{
		privKey = key.D.Bytes()
		curvOID = *key.PublicKey.Curve.CurveParams.OID
		keySize = key.Curve.Params().BitSize
		padded := padbytes(privKey, keySize)
		copy(padded[len(padded)-len(privKey):], privKey)
		algoPar, err := asn1.Marshal(pkcs8{
			Version: 0,
			Algo: pkix.AlgorithmIdentifier{
				asn1.ObjectIdentifier{
				curvOID,
				*sm2.Name2OID["id-GostR3411-94-CryptoProParamSet"],
			},
			PrivateKey: padded,
		})
		if err != nil {
			return nil, err
		}
		keySize = key.Curve.Size()
		return algoPar, nil
	}*/

	default:
		return nil, fmt.Errorf("x509: unknown public key algorithm")

		/*
			padded := make([]byte, keySize)
			copy(padded[len(padded)-len(privKey):], privKey)

			algoParams, err := asn1.Marshal(
				[]asn1.ObjectIdentifier{algo, *sm2.Name2OID["id-GostR3411-94-CryptoProParamSet"]})
			if err != nil {
				return nil, err
			}

			return asn1.Marshal(pkcs8{
				Version: 0,
				Algo: pkix.AlgorithmIdentifier{
					Algorithm:  *sm2.Name2OID["id-GostR3410-2001"],
					Parameters: asn1.RawValue{FullBytes: algoParams},
				},
				PrivateKey: paddedPrivateKey,
			})
		*/
	}

}
