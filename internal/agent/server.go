package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// requestTimeout bounds the wait for the request line, so a client that
// connects and sends nothing does not hold a connection.
const requestTimeout = 10 * time.Second

const maxRequest = 64 << 10

// Handler answers one request. Its context is canceled when the work machine
// hangs up, such as when the forward goes down.
type Handler func(context.Context, Request) Response

// Serve answers each connection on l with handle until ctx is done, and
// waits for the requests in progress before it returns.
func Serve(ctx context.Context, l net.Listener, handle Handler) error {
	stop := context.AfterFunc(ctx, func() { _ = l.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { serveConn(ctx, conn, handle) })
	}
}

func serveConn(ctx context.Context, conn net.Conn, handle Handler) {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	r := bufio.NewReader(io.LimitReader(conn, maxRequest))
	line, err := r.ReadBytes('\n')
	if err != nil {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	// The client sends nothing more, so a read returns only when it hangs up.
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		cancel()
	}()

	var resp Response
	var req Request
	switch {
	case json.Unmarshal(line, &req) != nil:
		resp = Response{Error: "malformed request"}
	case req.Version != Version:
		resp = Response{Error: fmt.Sprintf("this agent speaks protocol version %d, but the request has %d; install the same version on both machines", Version, req.Version)}
	default:
		resp = handle(ctx, req)
	}
	resp.Version = Version
	_ = json.NewEncoder(conn).Encode(resp)
}
