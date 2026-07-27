package cmd

import (
	"fmt"
	"io"
)

// out wraps a command's output stream and records the first write failure,
// turning later writes into no-ops.
//
// Every command here returns an error, so a failed write should surface as that
// error rather than vanish. Discarding it — which is what an unchecked
// fmt.Fprintln does — means `drillproof audit init > /full/disk` exits 0 having
// written nothing. The same idiom is used by internal/report.
type out struct {
	w   io.Writer
	err error
}

func newOut(w io.Writer) *out { return &out{w: w} }

func (o *out) printf(format string, args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprintf(o.w, format, args...)
}

func (o *out) println(args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprintln(o.w, args...)
}

func (o *out) print(args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprint(o.w, args...)
}

// Err returns the first write failure, if any. Commands return this.
func (o *out) Err() error { return o.err }
