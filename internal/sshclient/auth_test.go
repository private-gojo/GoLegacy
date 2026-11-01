package sshclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"

	"dev.go.core/internal/profile"
)

func TestKeyboardInteractivePasswordAuthentication(t *testing.T) {
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}

	serverConfig := &ssh.ServerConfig{
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("SSH authentication", "Password required", []string{"Password:"}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) != 1 || answers[0] != "test-password" {
				return nil, errors.New("invalid keyboard-interactive response")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		_, channels, requests, handshakeErr := ssh.NewServerConn(conn, serverConfig)
		if handshakeErr != nil {
			serverDone <- handshakeErr
			return
		}
		go ssh.DiscardRequests(requests)
		for channel := range channels {
			channel.Reject(ssh.UnknownChannelType, "not needed by authentication test")
		}
		serverDone <- nil
	}()

	address := listener.Addr().(*net.TCPAddr)
	client := &Client{}
	p := profile.Profile{
		Mode: profile.ModeDirect,
		Host: "127.0.0.1",
		Port: uint16(address.Port),
		Username: "test-user",
		Password: "test-password",
	}
	if err := client.Connect(p); err != nil {
		t.Fatalf("keyboard-interactive SSH authentication failed: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close SSH client: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("SSH test server handshake: %v", err)
	}
}
