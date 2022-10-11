package goio

import "testing"

type testWriteAll struct {
	n int
}

func (t *testWriteAll) Write(b []byte) (int, error) {
	if len(b) < 10 {
		return len(b), nil
	}
	return 10, nil
}

func TestWriteAll(t *testing.T) {
	tw := testWriteAll{}
	buf := make([]byte, 9998)
	n, err := WriteAll(&tw, buf)
	if n != len(buf) {
		t.Error(n, "!=", len(buf))
	}
	if err != nil {
		t.Error(err)
	}
}
