package keys

import (
    "fmt"
    "crypto/x509"
    "crypto/rsa"
    "crypto/rand"
    "encoding/pem"
)

func main() {

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

    if err != nil {
        fmt.Println(err)
    }

    privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)

    privateKeyBlock := pem.Block{   
        Type:    "RSA PRIVATE KEY",
        Headers: nil,
        Bytes:   privateKeyDer,
    }

    privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))

    publicKey := privateKey.PublicKey

    publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKey)

    if err != nil {
        fmt.Println(err)
    }
    
    publicKeyBlock := pem.Block{
        Type:    "PUBLIC KEY",
        Headers: nil,
        Bytes:   publicKeyDer,
    }

    publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

    fmt.Println(privateKeyPem)
    fmt.Println(publicKeyPem)   
}

