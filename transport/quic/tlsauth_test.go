package quic

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/udisondev/nodenet/identity"
)

func idFromByte(b byte) *identity.Identity {
	var seed [identity.SeedLen]byte
	for i := range seed {
		seed[i] = b
	}
	return identity.FromSeed(seed)
}

// certWithExt builds a self-signed cert carrying an arbitrary peerOID extension
// value (or none, if extVal is nil), for exercising verifyPeer's failure paths.
func certWithExt(t *testing.T, extVal []byte) [][]byte {
	t.Helper()
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	if extVal != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: peerOID, Value: extVal}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return [][]byte{der}
}

func TestVerifyPeerAcceptsOwnCert(t *testing.T) {
	id := idFromByte(7)
	cert, err := buildCert(id, rand.Reader)
	if err != nil {
		t.Fatalf("buildCert: %v", err)
	}
	got, err := verifyPeer(cert.Certificate)
	if err != nil {
		t.Fatalf("verifyPeer: %v", err)
	}
	if got != id.ID() {
		t.Fatalf("authenticated NodeID = %v, want %v", got, id.ID())
	}
}

func TestVerifyPeerDeterministic(t *testing.T) {
	// Same seed + same rand stream → identical cert and identical authenticated ID.
	a, err := buildCert(idFromByte(3), zeroReader{})
	if err != nil {
		t.Fatalf("buildCert a: %v", err)
	}
	b, err := buildCert(idFromByte(3), zeroReader{})
	if err != nil {
		t.Fatalf("buildCert b: %v", err)
	}
	ida, err := verifyPeer(a.Certificate)
	if err != nil {
		t.Fatalf("verifyPeer a: %v", err)
	}
	idb, err := verifyPeer(b.Certificate)
	if err != nil {
		t.Fatalf("verifyPeer b: %v", err)
	}
	if ida != idb {
		t.Fatal("verifyPeer not deterministic across identical inputs")
	}
}

func TestVerifyPeerRejects(t *testing.T) {
	id := idFromByte(9)

	t.Run("no-cert", func(t *testing.T) {
		if _, err := verifyPeer(nil); err != errNoCert {
			t.Fatalf("err = %v, want errNoCert", err)
		}
	})
	t.Run("no-extension", func(t *testing.T) {
		if _, err := verifyPeer(certWithExt(t, nil)); err != errNoExtension {
			t.Fatalf("err = %v, want errNoExtension", err)
		}
	})
	t.Run("malformed-extension", func(t *testing.T) {
		if _, err := verifyPeer(certWithExt(t, []byte{1, 2, 3})); err != errBadExtension {
			t.Fatalf("err = %v, want errBadExtension", err)
		}
	})
	t.Run("bad-signature", func(t *testing.T) {
		// Right shape, real ed_pub, but signature does not match the cert's SPKI.
		bad := encodePeerExt(peerExt{EdPub: id.EdPublic(), Sig: make([]byte, ed25519.SignatureSize)})
		if _, err := verifyPeer(certWithExt(t, bad)); err != errBadIdentitySig {
			t.Fatalf("err = %v, want errBadIdentitySig", err)
		}
	})
}

func TestTLSConfigAuthenticatesPeer(t *testing.T) {
	a := idFromByte(1)
	certA, err := buildCert(a, rand.Reader)
	if err != nil {
		t.Fatalf("buildCert: %v", err)
	}
	// The shared config's verify callback authenticates a valid peer cert (the
	// expected-ID comparison happens post-handshake in Dial, exercised by e2e).
	conf := tlsConfig(certA)
	if err := conf.VerifyPeerCertificate(certA.Certificate, nil); err != nil {
		t.Fatalf("valid peer cert rejected: %v", err)
	}
	if conf.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAnyClientCert", conf.ClientAuth)
	}
	if got := conf.VerifyPeerCertificate(nil, nil); got != errNoCert {
		t.Fatalf("empty chain: err = %v, want errNoCert", got)
	}
}

// zeroReader is a deterministic, infinite source of zero bytes for reproducible
// key generation in tests.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
