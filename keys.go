package keys

import (
    "crypto/x509"
    "crypto/rsa"
    "crypto/rand"
    "encoding/pem"
    "log"
)

func GenRSAKey(keyLength int) (string, string) {

    privateKeyRaw, err := rsa.GenerateKey(rand.Reader, keyLength)

    if err != nil {
        log.Fatal("Error generating keys")
    }

    privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKeyRaw)

    privateKeyBlock := pem.Block {   
        Type:    "RSA PRIVATE KEY",
        Headers: nil,
        Bytes:   privateKeyDer,
    }

    privateKey := string(pem.EncodeToMemory(&privateKeyBlock))

    publicKeyRaw := privateKeyRaw.PublicKey

    publicKeyDer, err := x509.MarshalPKIXPublicKey(&publicKeyRaw)

    if err != nil {
        log.Fatalf("Error serializing public key") 
    }
    
    publicKeyBlock := pem.Block {
        Type:    "PUBLIC KEY",
        Headers: nil,
        Bytes:   publicKeyDer,
    }

    publicKey := string(pem.EncodeToMemory(&publicKeyBlock))

    return privateKey, publicKey
}

