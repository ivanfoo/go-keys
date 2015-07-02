package urkel

import (
    "crypto/x509"
    "crypto/rsa"
    "crypto/rand"
    "encoding/pem"
    "log"
    "os"
)

func GenKey(keyLength int) (string, string) {

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

func GenKeyToFile(keyLength int, fileName string) {
    var privateKey, publicKey string
    privateKey, publicKey = GenKey(keyLength)
    file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY,0644)
   
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    if _, err = file.WriteString(privateKey); err != nil {
        log.Fatal(err)
    }

    file, err = os.OpenFile("rsa_key.pub", os.O_CREATE|os.O_WRONLY,0644)
   
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    if _, err = file.WriteString(publicKey); err != nil {
        log.Fatal(err)
    }
}


