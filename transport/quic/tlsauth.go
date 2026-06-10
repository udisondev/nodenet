package quic

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"time"

	"github.com/udisondev/nodenet/identity"
	"github.com/udisondev/nodenet/kad"
)

// This file holds the mutual-TLS machinery that authenticates a peer to its
// NodeID. The scheme is libp2p-style: a one-time certificate key per process,
// self-signed, carrying a custom X.509 extension that binds the long-lived
// Ed25519 identity to the cert key. The standard CA/hostname/expiry checks are
// disabled (InsecureSkipVerify); verifyPeer replaces them by checking the
// extension and recomputing NodeID = BLAKE2b(ed_pub).

// peerOID is the private-use object identifier of the identity extension. It is a
// level-1 protocol constant — both sides must agree on it — under an
// arbitrary private arc; the certificate is self-signed and only our own
// verifyPeer reads the extension, so no registered enterprise number is needed.
var peerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58147, 1, 1}

// alpn is the ALPN protocol name negotiated on every nodenet QUIC connection.
// A peer speaking a different protocol fails the TLS handshake before any frame.
const alpn = "nodenet/1"

var (
	errNoCert         = errors.New("quic: peer presented no certificate")
	errNoExtension    = errors.New("quic: certificate missing identity extension")
	errBadIdentitySig = errors.New("quic: identity signature does not verify")
)

// buildCert generates a one-time ECDSA P-256 key and self-signs a certificate
// carrying the identity extension {ed_pub, sig_ed(SPKI)} — the Ed25519 signature
// over the cert's SubjectPublicKeyInfo, which is what verifyPeer checks. rand is
// injected so tests are deterministic; production passes crypto/rand.Reader.
func buildCert(id *identity.Identity, rand io.Reader) (tls.Certificate, error) {
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Sign the cert's SubjectPublicKeyInfo DER, which equals the parsed leaf's
	// RawSubjectPublicKeyInfo — the exact bytes verifyPeer re-verifies over.
	spki, err := x509.MarshalPKIXPublicKey(&certKey.PublicKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	extVal := encodePeerExt(peerExt{EdPub: id.EdPublic(), Sig: id.Sign(spki)})

	// Validity window is irrelevant: InsecureSkipVerify disables expiry checks,
	// so fixed bounds keep buildCert deterministic given deterministic rand.
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nodenet"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{
			{Id: peerOID, Value: extVal},
		},
	}
	der, err := x509.CreateCertificate(rand, tmpl, tmpl, &certKey.PublicKey, certKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  certKey,
	}, nil
}

// verifyLeaf authenticates a peer from its parsed leaf certificate: it extracts
// the identity extension, verifies the Ed25519 signature over the leaf's
// SubjectPublicKeyInfo, and returns NodeID = BLAKE2b(ed_pub). It is pure.
func verifyLeaf(leaf *x509.Certificate) (kad.ID, error) {
	var raw []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(peerOID) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return kad.ID{}, errNoExtension
	}
	pe, err := decodePeerExt(raw)
	if err != nil {
		return kad.ID{}, err
	}
	if !ed25519.Verify(pe.EdPub, leaf.RawSubjectPublicKeyInfo, pe.Sig) {
		return kad.ID{}, errBadIdentitySig
	}
	return identity.DeriveID(pe.EdPub), nil
}

// verifyPeer parses the raw certificate chain a peer presented during the TLS
// handshake and authenticates its leaf. It is the VerifyPeerCertificate callback
// body, run on both the dial and accept sides; it authenticates only — neither
// side embeds the expected-ID check here. The dialer instead re-derives the peer
// ID after the handshake (peerIDFromConn) and compares it to the ID it asked for,
// which keeps the comparison off the fragile TLS error-propagation path.
func verifyPeer(rawCerts [][]byte) (kad.ID, error) {
	if len(rawCerts) == 0 {
		return kad.ID{}, errNoCert
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return kad.ID{}, err
	}
	return verifyLeaf(leaf)
}

// peerIDFromConn re-derives the authenticated NodeID from a completed handshake's
// negotiated state, reusing the already-parsed peer leaf certificate. The
// handshake only completes if verifyPeer accepted the cert, so this cannot fail
// on a live connection except for the defensive no-cert case.
func peerIDFromConn(state tls.ConnectionState) (kad.ID, error) {
	if len(state.PeerCertificates) == 0 {
		return kad.ID{}, errNoCert
	}
	return verifyLeaf(state.PeerCertificates[0])
}

// tlsConfig is the single mutual-TLS config used for both listening and dialing:
// it presents our cert, requires the peer to present one, and authenticates it
// via verifyPeer. The standard CA/hostname/expiry checks are disabled;
// authentication is entirely NodeID-based. It is safe for concurrent reuse across
// connections (never mutated after construction).
func tlsConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpn},
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error { _, err := verifyPeer(rawCerts); return err },
	}
}
