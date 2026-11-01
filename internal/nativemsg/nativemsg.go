// Package nativemsg implements the framing of Chrome native messaging: a
// uint32 length in native byte order followed by that many bytes of JSON.
package nativemsg

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	maxRead  = 1 << 20
	maxWrite = 1 << 20
)

// Read reads one message into v.
func Read(r io.Reader, v any) error {
	var n uint32
	if err := binary.Read(r, binary.NativeEndian, &n); err != nil {
		return err
	}
	if n > maxRead {
		return fmt.Errorf("message of %d bytes exceeds %d", n, maxRead)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, v)
}

// Write writes v as one message.
func Write(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxWrite {
		return fmt.Errorf("message of %d bytes exceeds %d", len(b), maxWrite)
	}
	if err := binary.Write(w, binary.NativeEndian, uint32(len(b))); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
