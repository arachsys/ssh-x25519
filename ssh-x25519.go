package main

import "fmt"
import "io"
import "os"
import "crypto/ed25519"
import "crypto/sha512"
import "filippo.io/edwards25519"
import "golang.org/x/crypto/ssh"
import "golang.org/x/term"

func clamp(digest [64]byte) []byte {
  digest[0] &= 0xf8
  digest[31] &= 0x7f
  digest[31] |= 0x40
  return digest[:32]
}

func die(status int, message string) {
  fmt.Fprintln(os.Stderr, message)
  os.Exit(status)
}

func getpass() []byte {
  if term.IsTerminal(int(os.Stdin.Fd())) {
    os.Stdin.Write([]byte("Enter passphrase: "))
    pass, _ := term.ReadPassword(int(os.Stdin.Fd()))
    os.Stdin.Write([]byte("\n"))
    return pass
  }
  pass, _ := io.ReadAll(os.Stdin)
  return pass
}

func main() {
  if len(os.Args) != 2 {
    die(64, "Usage: " + os.Args[0] + " KEYFILE")
  }

  data, err := os.ReadFile(os.Args[1])
  if err != nil {
    die(1, err.Error())
  }

  public, _, _, _, err := ssh.ParseAuthorizedKey(data)
  if public, ok := public.(ssh.CryptoPublicKey); ok {
    if public, ok := public.CryptoPublicKey().(ed25519.PublicKey); ok {
      edwards, err := new(edwards25519.Point).SetBytes(public)
      if err == nil {
        os.Stdout.Write(edwards.BytesMontgomery())
        return
      }
    }
  }

  private, err := ssh.ParseRawPrivateKey(data)
  if _, ok := err.(*ssh.PassphraseMissingError); ok {
    if pass := getpass(); pass != nil {
      private, err = ssh.ParseRawPrivateKeyWithPassphrase(data, pass)
    }
    if err != nil {
      die(1, os.Args[1] + " could not be decrypted")
    }
  }

  if private, ok := private.(*ed25519.PrivateKey); ok {
    os.Stdout.Write(clamp(sha512.Sum512(private.Seed())))
    return
  }

  die(1, os.Args[1] + " is not an ssh-ed25519 keyfile")
}
