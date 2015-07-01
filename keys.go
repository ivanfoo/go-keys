package keys

import (
    "crypto/x509"
    "crypto/rsa"
    "crypto/rand"
    "encoding/pem"
    "log"
)

func GenRSAKeys() {

    keys := make(map[string]string )

    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)

    if err != nil {
        log.Fatalf("Error generating private key: ", err) 
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
        log.Fatalf("Error generating public key: ", err) 
    }
    
    publicKeyBlock := pem.Block{
        Type:    "PUBLIC KEY",
        Headers: nil,
        Bytes:   publicKeyDer,
    }

    publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))

    keys["privateKey"] = privateKeyPem
    keys["publicKey"] = publicKeyPem

    return keys
}

