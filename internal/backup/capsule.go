package backup

import (
	"os"

	"github.com/Busness-app/ky-primitives/capsule"
)

// BackupFile is one member of a capsule's payload, as the collectors produce it.
type BackupFile struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode int64  `json:"mode"`
}

// Seal writes a kycap/3 container sealed to the suite recovery public key. The product
// holds nothing afterwards that opens it; only the custodians' shares do.
func Seal(serviceName, appVersion string, files []BackupFile, deps, recipe map[string]any, key RecoveryKey) ([]byte, capsule.Manifest, error) {
	if key.Public.IsZero() {
		return nil, capsule.Manifest{}, ErrNotPaired
	}
	return capsule.Seal(serviceName, appVersion, toCapsuleFiles(files), deps, recipe, key.Threshold, key.TotalShares, key.Public)
}

func toCapsuleFiles(files []BackupFile) []capsule.File {
	out := make([]capsule.File, 0, len(files))
	for _, f := range files {
		out = append(out, capsule.File{Path: f.Path, Content: f.Data, Mode: os.FileMode(f.Mode)})
	}
	return out
}
