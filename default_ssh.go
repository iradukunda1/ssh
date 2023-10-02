package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func main() {
	if err := StartShhSrv("hell"); err != nil {
		log.Fatalln(err)
	}
}

func StartShhSrv(host string) error {

	config := &ssh.ServerConfig{
		Config: ssh.Config{
			Ciphers: []string{
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
			},
		},
		NoClientAuth: true,
		BannerCallback: func(conn ssh.ConnMetadata) string {
			x := fmt.Sprintf("Welcome to %s\n", conn.User())
			x += fmt.Sprintf("Time:%s\n", time.Now().Format(time.RFC1123))
			x += fmt.Sprintf("Host:%s\n", host)
			return x
		},
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key... %v", err)
	}

	private, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create SSH signer... %v", err)
	}

	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		return fmt.Errorf("failed to listen on 22 (%v)", err)
	}

	fmt.Println("Listening on 22...")

	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept incoming connection (%v)\n", err)
			continue
		}
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			fmt.Printf("Failed to handshake (%v)\n", err)
			continue
		}

		fmt.Printf("New SSH connection from %s (%s)\n", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go ssh.DiscardRequests(reqs)
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		fmt.Printf("Could not accept channel (%v)\n", err)
		return
	}

	// Fire up bash for this session
	bash := exec.Command("bash")

	// Prepare teardown function
	close := func() {
		connection.Close()
		if bash.Process != nil {
			_, err := bash.Process.Wait()
			if err != nil {
				fmt.Printf("Failed to exit bash (%v)\n", err)
			}
		}
		fmt.Println("Session closed")
	}

	// Allocate a terminal for this channel
	fmt.Println("Creating pty...")
	ptmx, err := pty.Start(bash)
	if err != nil {
		fmt.Printf("Could not start pty (%v)\n", err)
		close()
		return
	}

	//pipe session to bash and visa-versa
	var once sync.Once
	go func() {
		io.Copy(connection, ptmx)
		once.Do(close)
	}()
	go func() {
		io.Copy(ptmx, connection)
		once.Do(close)
	}()

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {
		for req := range requests {
			switch req.Type {
			case "shell":
				fmt.Println("Starting shell...")
				// We only accept the default shell
				// (i.e. no command in the Payload)
				if len(req.Payload) == 0 {
					req.Reply(true, nil)
				}
			case "pty-req":
				fmt.Println("Starting pty-req...")
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(ptmx.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				fmt.Println("Starting window...")
				w, h := parseDims(req.Payload)
				SetWinsize(ptmx.Fd(), w, h)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
