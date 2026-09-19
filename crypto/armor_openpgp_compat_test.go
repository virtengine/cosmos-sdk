package crypto_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/crypto"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

// The armor encoder used to be github.com/golang.org/x/crypto/openpgp/armor,
// which is unmaintained and flagged as unsafe by design (GO-2026-5932). It has
// been replaced with github.com/ProtonMail/go-crypto/openpgp/armor.
//
// The two encoders are wire-compatible, with one deliberate difference: the old
// encoder emitted header lines in Go map-iteration order (unspecified and
// therefore *nondeterministic* between runs), while the new one sorts them. The
// block type, header set, base64 body, CRC24 checksum and line wrapping are
// identical. These tests pin that contract so a future swap cannot silently
// change stored key armor.

// legacyArmorPubKey is a fixed artifact in the shape the retired encoder
// produced: the header lines appear in a non-sorted order, which the old
// encoder emitted at random. Decoding must be insensitive to that order,
// otherwise keyring files written before the migration would stop loading.
const legacyArmorPubKey = `-----BEGIN TENDERMINT PUBLIC KEY-----
version: 0.0.1
type: secp256k1

Z29sZGVuLWJvZHk=
=Innj
-----END TENDERMINT PUBLIC KEY-----
`

// armorPubKeyGolden is the exact output of the current encoder for the same
// input, with header lines sorted. If this string changes, the on-disk key
// format changed and the change is a migration, not a refactor.
const armorPubKeyGolden = `-----BEGIN TENDERMINT PUBLIC KEY-----
type: secp256k1
version: 0.0.1

Z29sZGVuLWJvZHk=
=Innj
-----END TENDERMINT PUBLIC KEY-----`

const armorInfoGolden = `-----BEGIN TENDERMINT KEY INFO-----
type: Info
version: 0.0.0

cGxhaW4tdGV4dA==
=NRk2
-----END TENDERMINT KEY INFO-----`

// armorNoHeadersGolden covers the nil-header path.
const armorNoHeadersGolden = `-----BEGIN MINT TEST-----

c29tZWRhdGE=
=dcN7
-----END MINT TEST-----`

func TestArmorWireFormatGolden(t *testing.T) {
	require.Equal(t, armorPubKeyGolden,
		crypto.EncodeArmor("TENDERMINT PUBLIC KEY",
			map[string]string{"type": "secp256k1", "version": "0.0.1"},
			[]byte("golden-body")))

	require.Equal(t, armorInfoGolden,
		crypto.EncodeArmor("TENDERMINT KEY INFO",
			map[string]string{"type": "Info", "version": "0.0.0"},
			[]byte("plain-text")))

	require.Equal(t, armorNoHeadersGolden,
		crypto.EncodeArmor("MINT TEST", nil, []byte("somedata")))
}

func TestArmorDecodesLegacyHeaderOrder(t *testing.T) {
	// The legacy artifact and the current golden differ only in header order.
	require.NotEqual(t, legacyArmorPubKey, armorPubKeyGolden)

	blockType, header, data, err := crypto.DecodeArmor(legacyArmorPubKey)
	require.NoError(t, err)
	require.Equal(t, "TENDERMINT PUBLIC KEY", blockType)
	require.Equal(t, map[string]string{"version": "0.0.1", "type": "secp256k1"}, header)
	require.Equal(t, []byte("golden-body"), data)

	// The public-key helper must accept it too.
	bz, algo, err := crypto.UnarmorPubKeyBytes(legacyArmorPubKey)
	require.NoError(t, err)
	require.Equal(t, []byte("golden-body"), bz)
	require.Equal(t, "secp256k1", algo)
}

// TestArmorHeaderOrderIsDeterministic is a regression guard: the retired
// encoder ranged over the header map without sorting, so encoding the same key
// twice could produce different bytes. The replacement must be stable.
func TestArmorHeaderOrderIsDeterministic(t *testing.T) {
	headers := map[string]string{
		"type":    "secp256k1",
		"version": "0.0.1",
		"kdf":     "argon2",
		"salt":    "FF00FF00FF00FF00",
	}

	first := crypto.EncodeArmor("TENDERMINT PRIVATE KEY", headers, []byte("body"))
	for i := 0; i < 500; i++ {
		require.Equal(t, first, crypto.EncodeArmor("TENDERMINT PRIVATE KEY", headers, []byte("body")),
			"armor encoding is not deterministic on iteration %d", i)
	}

	// Headers must be emitted in sorted order.
	lines := strings.Split(first, "\n")
	require.Equal(t, "kdf: argon2", lines[1])
	require.Equal(t, "salt: FF00FF00FF00FF00", lines[2])
	require.Equal(t, "type: secp256k1", lines[3])
	require.Equal(t, "version: 0.0.1", lines[4])
}

// headerPermutations returns every ordering of len(n) header lines.
func headerPermutations(n int) [][]int {
	var out [][]int
	var rec func(cur []int, used []bool)
	rec = func(cur []int, used []bool) {
		if len(cur) == n {
			cp := make([]int, n)
			copy(cp, cur)
			out = append(out, cp)
			return
		}
		for i := 0; i < n; i++ {
			if used[i] {
				continue
			}
			used[i] = true
			rec(append(cur, i), used)
			used[i] = false
		}
	}
	rec(nil, make([]bool, n))
	return out
}

// reorderHeaders rewrites armorStr with its header lines in the given order.
func reorderHeaders(t *testing.T, armorStr string, order []int) string {
	t.Helper()
	lines := strings.Split(armorStr, "\n")

	var idx []int
	for i, l := range lines {
		if strings.Contains(l, ": ") && !strings.HasPrefix(l, "-----") {
			idx = append(idx, i)
		}
	}
	require.Len(t, idx, len(order))

	orig := make([]string, len(idx))
	for i, lineIdx := range idx {
		orig[i] = lines[lineIdx]
	}
	for i, lineIdx := range idx {
		lines[lineIdx] = orig[order[i]]
	}
	return strings.Join(lines, "\n")
}

// TestArmorPrivateKeyArtifactsSurviveHeaderReordering re-encrypts a private key
// with the current encoder and then rewrites the header lines into every
// possible order. Every variant must still decrypt to the same key, because
// artifacts already on disk were written in arbitrary header orders by the
// retired encoder.
func TestArmorPrivateKeyArtifactsSurviveHeaderReordering(t *testing.T) {
	privKey := secp256k1.GenPrivKey()
	const passphrase = "passphrase"

	armored := crypto.EncryptArmorPrivKey(privKey, passphrase, "secp256k1")

	_, _, err := crypto.UnarmorDecryptPrivKey(armored, "wrongpassphrase")
	require.Error(t, err, "wrong passphrase must still fail")

	perms := headerPermutations(3)
	require.Len(t, perms, 6)
	for _, p := range perms {
		variant := reorderHeaders(t, armored, p)

		got, algo, err := crypto.UnarmorDecryptPrivKey(variant, passphrase)
		require.NoError(t, err, "header order %v must remain decryptable", p)
		require.True(t, privKey.Equals(got), "header order %v changed the decrypted key", p)
		require.Equal(t, "secp256k1", algo, "header order %v lost the algo header", p)
	}
}

// TestArmorRoundTripAcrossLineWrapBoundaries exercises the base64 line wrapper,
// which emits 48 raw bytes per line and therefore has off-by-one hazards.
func TestArmorRoundTripAcrossLineWrapBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 2, 47, 48, 49, 63, 64, 95, 96, 97, 100, 1000, 4096} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i % 251)
		}

		armored := crypto.EncodeArmor("MINT TEST", map[string]string{"type": "Info"}, body)

		blockType, header, got, err := crypto.DecodeArmor(armored)
		require.NoError(t, err, "n=%d", n)
		assert.Equal(t, "MINT TEST", blockType, "n=%d", n)
		assert.Equal(t, map[string]string{"type": "Info"}, header, "n=%d", n)
		assert.Equal(t, body, got, "n=%d", n)
	}
}
