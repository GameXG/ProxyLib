package goio

import "io"

type Flusher interface {
	Flush() error
}
type WriteFlushCloser interface {
	io.Writer
	Flusher
	io.Closer
}
type nopCloser struct {
	io.Writer
}

func (nopCloser) Close() error {
	return nil
}

func NopCloser(w io.Writer) io.WriteCloser {
	return nopCloser{w}
}

func WriteAll(w io.Writer, buf []byte) (n int, err error) {
	b := buf
	for len(b) != 0 {
		ln, lerr := w.Write(b)

		n += ln
		b = b[ln:]

		if lerr != nil {
			return n, lerr
		}
	}
	return
}
