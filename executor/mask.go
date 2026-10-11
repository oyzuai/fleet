package executor

import (
	"encoding/base64"
	"io"

	"github.com/oyzuai/fleet/internal/masking"
)

type maskWriter = masking.Writer

func newMaskWriter(dst io.Writer, forms []string) *maskWriter { return masking.NewWriter(dst, forms) }
func maskForms(values ...string) []string                     { return masking.Forms(values...) }
func base64Core(enc *base64.Encoding, v string, align int) string {
	return masking.Base64Core(enc, v, align)
}

const masked = "***"

func replaceForms(s string, forms []string) string { return masking.Replace(s, forms) }
