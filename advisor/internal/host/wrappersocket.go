package host

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The client half of the Advisor's one root socket (ADR 0025).
//
// The Advisor never runs the node wrapper through sudo. It connects to
// /run/aperire/node-wrapper<-instance>.sock, sends one line, and reads the
// wrapper's output back in frames. On the other side of the socket,
// aperire-wrapper-broker (root, one process per connection) checks this
// process's uid, checks the verb and every argument against a fixed table,
// and runs the root-owned wrapper copy. Connecting needs no privilege, so
// this service's unit runs NoNewPrivileges=true on every systemd, including
// 249, where sudo could never work under the sandbox.
//
// The wire format, both directions, is the one the broker documents:
//
//	request   "v1 <verb> [arg] [arg]\n", single spaces, every token from
//	          [A-Za-z0-9._:=-]
//	answer    frames: one type byte ('a' accepted and about to run, 'o'
//	          stdout, 'e' stderr, 'x' exit code as ASCII, always last), a
//	          4-byte big-endian length, the bytes
//
// Errors read the way ExecRunner's always have: "<wrapper>: exit status N:
// <stderr>". Callers find the wrapper's own sentence after "wrapper: " in
// that string (wrapperReason), and nothing about that changes.

const (
	wrapperSocketProtocol = "v1"
	wrapperSocketMaxToken = 128
	// The broker refuses past 1024 bytes; checked here too so a caller
	// gets the reason without a round trip.
	wrapperSocketMaxRequest = 1024
	// How many times a connection that closes with no frame at all is
	// tried again. That is systemd at MaxConnections: it accepts and closes
	// at once. Anything else that closes early has sent a frame first.
	wrapperSocketRetries = 6
	// A frame larger than this is not something the broker sends; it is a
	// broken stream, and reading it would be an unbounded allocation.
	wrapperSocketMaxFrame = 1 << 20
)

var wrapperSocketToken = regexp.MustCompile(`^[A-Za-z0-9._:=-]{1,128}$`)

// WrapperExitError is a wrapper call that ran and exited non-zero, carried
// across the socket. Its text is exactly what ExecRunner produced for the
// same failure when the wrapper was a local process.
type WrapperExitError struct {
	Name   string
	Code   int
	Stderr string
}

func (e *WrapperExitError) Error() string {
	if e.Stderr != "" {
		return fmt.Sprintf("%s: exit status %d: %s", e.Name, e.Code, e.Stderr)
	}
	return fmt.Sprintf("%s: exit status %d", e.Name, e.Code)
}

// ExitCode mirrors exec.ExitError's accessor for a caller that asks.
func (e *WrapperExitError) ExitCode() int { return e.Code }

// SocketForWrapper is the socket an installed wrapper copy is reached
// through: /usr/local/sbin/aperire-node-wrapper -> /run/aperire/node-
// wrapper.sock, and the -<instance> suffix carried across. Used when a unit
// still names --sudo-wrapper, so an Advisor whose unit an update has not
// rewritten yet comes up on the socket rather than on sudo or in a crash
// loop. Empty for a path that is not an installed wrapper name.
func SocketForWrapper(wrapper string) string {
	base := filepath.Base(wrapper)
	const stem = "aperire-node-wrapper"
	if base != stem && !strings.HasPrefix(base, stem+"-") {
		return ""
	}
	return "/run/aperire/node-wrapper" + strings.TrimPrefix(base, stem) + ".sock"
}

// wrapperRequest builds and checks the one request line.
func wrapperRequest(args []string) ([]byte, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no verb to send to the wrapper socket")
	}
	for _, a := range args {
		if !wrapperSocketToken.MatchString(a) {
			return nil, fmt.Errorf("refusing to send %q to the wrapper socket: every word has to be 1 to %d characters from [A-Za-z0-9._:=-], and a path is never one", a, wrapperSocketMaxToken)
		}
	}
	line := wrapperSocketProtocol + " " + strings.Join(args, " ") + "\n"
	if len(line) > wrapperSocketMaxRequest {
		return nil, fmt.Errorf("refusing to send a request of %d bytes to the wrapper socket; the limit is %d", len(line), wrapperSocketMaxRequest)
	}
	return []byte(line), nil
}

// errNoFrame is a connection closed before anything came back: systemd at
// its connection limit. The broker sends its 'a' frame before it runs
// anything, so no frame at all means nothing ran, and trying again cannot
// repeat an action.
var errNoFrame = errors.New("the wrapper socket closed without answering")

// wrapperSocketCall sends one call and reads the whole answer. sink, when
// set, is handed each complete line of stdout and stderr as it lands, the
// same contract as ExecRunner.RunLines.
func wrapperSocketCall(ctx context.Context, sock, name string, sink func(string), args ...string) ([]byte, error) {
	req, err := wrapperRequest(args)
	if err != nil {
		return nil, err
	}
	delay := 100 * time.Millisecond
	for attempt := 0; ; attempt++ {
		out, err := wrapperSocketOnce(ctx, sock, name, req, sink)
		if !errors.Is(err, errNoFrame) || attempt >= wrapperSocketRetries {
			if errors.Is(err, errNoFrame) {
				return nil, fmt.Errorf("%s: %w at %s after %d tries (is aperire-node-wrapper.socket running? systemctl status for the socket unit says)", name, err, sock, attempt+1)
			}
			return out, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", name, ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
	}
}

func wrapperSocketOnce(ctx context.Context, sock, name string, req []byte, sink func(string)) ([]byte, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("%s: could not reach the wrapper socket %s: %w", name, sock, err)
	}
	defer conn.Close()
	// A cancelled context closes the connection, which is how the broker
	// learns the caller has gone: a read-only verb is stopped there, and a
	// verb that changes something runs to its end with nobody reading.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-stop:
		}
	}()
	if _, err := conn.Write(req); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", name, ctx.Err())
		}
		return nil, errNoFrame
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	var mu sync.Mutex
	lineOut := newLineSplitter(sink, &mu)
	lineErr := newLineSplitter(sink, &mu)
	br := bufio.NewReaderSize(conn, 64<<10)
	frames := 0
	hdr := make([]byte, 5)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if ctx.Err() != nil {
				return stdout.Bytes(), fmt.Errorf("%s: %w", name, ctx.Err())
			}
			if frames == 0 && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || isConnReset(err)) {
				return nil, errNoFrame
			}
			return stdout.Bytes(), fmt.Errorf("%s: the wrapper socket closed before the wrapper finished: %w", name, err)
		}
		n := binary.BigEndian.Uint32(hdr[1:])
		if n > wrapperSocketMaxFrame {
			return stdout.Bytes(), fmt.Errorf("%s: the wrapper socket sent a %d-byte frame, which no answer has; the stream is not one this client understands", name, n)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(br, body); err != nil {
			if ctx.Err() != nil {
				return stdout.Bytes(), fmt.Errorf("%s: %w", name, ctx.Err())
			}
			return stdout.Bytes(), fmt.Errorf("%s: the wrapper socket closed mid-answer: %w", name, err)
		}
		frames++
		switch hdr[0] {
		case 'a':
		case 'o':
			stdout.Write(body)
			lineOut.write(body)
		case 'e':
			stderr.Write(body)
			lineErr.write(body)
		case 'x':
			lineOut.flush()
			lineErr.flush()
			code, cerr := strconv.Atoi(string(body))
			if cerr != nil {
				return stdout.Bytes(), fmt.Errorf("%s: the wrapper socket sent an exit code that is not a number: %q", name, body)
			}
			if code == 0 {
				return stdout.Bytes(), nil
			}
			tail := strings.TrimSpace(stderr.String())
			if sink != nil {
				// RunLines has always carried only the end of a long failure.
				tail = lastLines(tail, 20)
			}
			return stdout.Bytes(), &WrapperExitError{Name: name, Code: code, Stderr: tail}
		default:
			return stdout.Bytes(), fmt.Errorf("%s: the wrapper socket sent a frame of type %q, which this client does not know", name, hdr[0])
		}
	}
}

func isConnReset(err error) bool {
	var ne *net.OpError
	return errors.As(err, &ne) && strings.Contains(ne.Err.Error(), "connection reset")
}

// lineSplitter hands complete lines to a sink as bytes arrive in arbitrary
// frames, the same thing drainLines does for a pipe.
type lineSplitter struct {
	sink func(string)
	mu   *sync.Mutex
	buf  []byte
}

func newLineSplitter(sink func(string), mu *sync.Mutex) *lineSplitter {
	return &lineSplitter{sink: sink, mu: mu}
}

func (l *lineSplitter) write(b []byte) {
	if l.sink == nil {
		return
	}
	l.buf = append(l.buf, b...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			return
		}
		line := strings.TrimRight(string(l.buf[:i]), "\r")
		l.buf = l.buf[i+1:]
		if line != "" {
			l.mu.Lock()
			l.sink(line)
			l.mu.Unlock()
		}
	}
}

func (l *lineSplitter) flush() {
	if l.sink == nil || len(l.buf) == 0 {
		return
	}
	line := strings.TrimRight(string(l.buf), "\r\n")
	l.buf = nil
	if line != "" {
		l.mu.Lock()
		l.sink(line)
		l.mu.Unlock()
	}
}
