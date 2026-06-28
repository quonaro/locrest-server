package chvdtunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/jpillora/chisel/share/cio"
	"github.com/jpillora/chisel/share/settings"
	"github.com/jpillora/sizestr"
	"golang.org/x/crypto/ssh"
)

// pipeListener is a net.Listener backed by a channel of net.Conns.
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 10),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.ch:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return conn, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
	})
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

func (l *pipeListener) inject(conn net.Conn) {
	select {
	case l.ch <- conn:
	case <-l.closed:
	}
}

// Global registry of proxy pipes keyed by server-side port (LocalPort).
var (
	proxyPipes   = make(map[int]*pipeListener)
	proxyPipesMu sync.RWMutex
)

// RegisterProxyPipe registers a pipe listener for a given port.
func RegisterProxyPipe(port int, pl *pipeListener) {
	proxyPipesMu.Lock()
	proxyPipes[port] = pl
	proxyPipesMu.Unlock()
}

// GetProxyPipe returns the injection channel for a given port, or nil if not found.
func GetProxyPipe(port int) chan net.Conn {
	proxyPipesMu.RLock()
	pl := proxyPipes[port]
	proxyPipesMu.RUnlock()
	if pl == nil {
		return nil
	}
	return pl.ch
}

// UnregisterProxyPipe removes a pipe listener for a given port.
func UnregisterProxyPipe(port int) {
	proxyPipesMu.Lock()
	delete(proxyPipes, port)
	proxyPipesMu.Unlock()
}

//sshTunnel exposes a subset of Tunnel to subtypes
type sshTunnel interface {
	getSSH(ctx context.Context) ssh.Conn
}

//Proxy is the inbound portion of a Tunnel
type Proxy struct {
	*cio.Logger
	sshTun sshTunnel
	id     int
	count  int
	remote *settings.Remote
	dialer net.Dialer
	pipe   *pipeListener
	mu     sync.Mutex
}

//NewProxy creates a Proxy
func NewProxy(logger *cio.Logger, sshTun sshTunnel, index int, remote *settings.Remote) (*Proxy, error) {
	id := index + 1
	p := &Proxy{
		Logger: logger.Fork("proxy#%s", remote.String()),
		sshTun: sshTun,
		id:     id,
		remote: remote,
	}
	if err := p.listen(); err != nil {
		return nil, err
	}
	if p.pipe != nil {
		port, _ := strconv.Atoi(remote.LocalPort)
		if port > 0 {
			RegisterProxyPipe(port, p.pipe)
		}
	}
	return p, nil
}

func (p *Proxy) listen() error {
	if p.remote.Stdio {
		//TODO check if pipes active?
	} else if p.remote.LocalProto == "tcp" {
		p.pipe = newPipeListener()
		p.Infof("Listening (pipe)")
	} else {
		return p.Errorf("unsupported local proto for pipe mode")
	}
	return nil
}

//Run enables the proxy and blocks while its active,
//close the proxy by cancelling the context.
func (p *Proxy) Run(ctx context.Context) error {
	if p.remote.Stdio {
		return p.runStdio(ctx)
	}
	return p.runPipe(ctx)
}

func (p *Proxy) runStdio(ctx context.Context) error {
	defer p.Infof("Closed")
	for {
		p.pipeRemote(ctx, cio.Stdio)
		select {
		case <-ctx.Done():
			return nil
		default:
			// the connection is not ready yet, keep waiting
		}
	}
}

func (p *Proxy) runPipe(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			p.pipe.Close()
		case <-done:
		}
	}()
	defer func() {
		close(done)
		if p.pipe != nil {
			port, _ := strconv.Atoi(p.remote.LocalPort)
			if port > 0 {
				UnregisterProxyPipe(port)
			}
		}
	}()
	for {
		src, err := p.pipe.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				//listener closed
				err = nil
			default:
				p.Infof("Accept error: %s", err)
			}
			return err
		}
		go p.pipeRemote(ctx, src)
	}
}

func (p *Proxy) pipeRemote(ctx context.Context, src io.ReadWriteCloser) {
	defer src.Close()

	p.mu.Lock()
	p.count++
	cid := p.count
	p.mu.Unlock()

	l := p.Fork("conn#%d", cid)
	l.Debugf("Open")
	sshConn := p.sshTun.getSSH(ctx)
	if sshConn == nil {
		l.Debugf("No remote connection")
		return
	}
	//ssh request for tcp connection for this proxy's remote
	dst, reqs, err := sshConn.OpenChannel("chisel", []byte(p.remote.Remote()))
	if err != nil {
		l.Infof("Stream error: %s", err)
		return
	}
	go ssh.DiscardRequests(reqs)
	//then pipe
	s, r := cio.Pipe(src, dst)
	l.Debugf("Close (sent %s received %s)", sizestr.ToString(s), sizestr.ToString(r))
}
