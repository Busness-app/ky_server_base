package backup_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Busness-app/ky_server_base/internal/backup"
)

// The suite carries more than one Shamir implementation behind an identical API.
// These vectors are the contract that keeps them interchangeable: a share set
// written by any product must reconstruct here, byte for byte. A change that
// breaks a vector is a breaking change to every recovery kit already issued.
//
// Split draws fresh randomness per call, so only the combine direction is fixed.

type shamirVectorFile struct {
	Vectors []struct {
		Name   string `json:"name"`
		K      int    `json:"k"`
		N      int    `json:"n"`
		Secret string `json:"secret_hex"`
		Shares []struct {
			Index int    `json:"index"`
			Data  string `json:"data_hex"`
		} `json:"shares"`
		Subset []int `json:"combine_subset"`
	} `json:"vectors"`
}

func TestShamirGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/shamir-vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f shamirVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("vector file is empty")
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			want, err := hex.DecodeString(v.Secret)
			if err != nil {
				t.Fatalf("decode secret: %v", err)
			}
			if len(v.Shares) != v.N {
				t.Fatalf("vector has %d shares, want n=%d", len(v.Shares), v.N)
			}

			all := make([]backup.Share, len(v.Shares))
			for i, s := range v.Shares {
				data, err := hex.DecodeString(s.Data)
				if err != nil {
					t.Fatalf("decode share %d: %v", s.Index, err)
				}
				all[i] = backup.Share{Index: s.Index, Data: data}
			}

			// CombineShares consumes the first k it is given, so the subset is
			// chosen by the caller — exactly as a restore flow does.
			use := all
			if v.Subset != nil {
				use = make([]backup.Share, len(v.Subset))
				for i, p := range v.Subset {
					use[i] = all[p]
				}
			}

			got, err := backup.CombineShares(use, v.K)
			if err != nil {
				t.Fatalf("CombineShares: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("reconstructed secret does not match vector\n got %x\nwant %x", got, want)
			}
		})
	}
}
