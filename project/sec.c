#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void insert_type(uint8_t **buf, uint8_t type)
{
    memcpy(*buf, &type, 1);
    *buf += 1;
}

void insert_length(uint8_t **buf, uint16_t length)
{
    length = htons(length);
    memcpy(*buf, &length, 2);
    *buf += 2;
}

void init_sec(int initial_state)
{
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND)
    {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    }
    else if (state_sec == SERVER_CLIENT_HELLO_AWAIT)
    {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }
    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t *buf, size_t max_length)
{
    // This passes it directly to standard input (working like Project 1)
    // return input_io(buf, max_length);
    uint8_t *buffer = buf;

    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        fprintf(stderr, "SEND CLIENT HELLO \n");

        /* Insert Client Hello sending logic here */
        // Insert type and length for message
        insert_type(&buffer, CLIENT_HELLO);
        insert_length(&buffer, NONCE_SIZE + 3);

        // Insert type and length for nonce
        insert_type(&buffer, NONCE_CLIENT_HELLO);
        insert_length(&buffer, NONCE_SIZE);

        // Copy nonce into buffer
        memcpy(buffer, nonce, NONCE_SIZE);
        // // Copy nonce into peer_nonce for peer to sign later
        // memcpy(peer_nonce, nonce, NONCE_SIZE);
        buffer += NONCE_SIZE;

        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        // print_hex(buf, buffer - buf);
        print_tlv(buf, buffer - buf);
        return buffer - buf;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        /* Insert Server Hello sending logic here */
        fprintf(stderr, "SEND SERVER HELLO \n");

        // Insert type for message
        insert_type(&buffer, SERVER_HELLO);

        // Don't know total length yet
        uint16_t *msg_buf = (uint16_t *)buffer; // Save to calculate total length
        buffer += 2;

        // Insert type and length for nonce
        insert_type(&buffer, NONCE_SERVER_HELLO);
        insert_length(&buffer, NONCE_SIZE);

        // Copy server nonce into buffer
        memcpy(buffer, nonce, NONCE_SIZE);
        buffer += NONCE_SIZE;

        // Copy certificate tlv into buffer
        memcpy(buffer, certificate, cert_size);
        buffer += (uint8_t)cert_size;

        // Insert type for signature
        insert_type(&buffer, NONCE_SIGNATURE_SERVER_HELLO);

        // Don't know length of signature yet so store pointer
        uint16_t *sig_len_insert = (uint16_t *)buffer;
        buffer += 2;

        // Sign client nonce stored in peer_nonce with private key and store in buffer
        size_t sig_size = sign(peer_nonce, NONCE_SIZE, buffer);
        buffer += (uint16_t)sig_size;

        // Set length of signature
        *sig_len_insert = htons((uint16_t)sig_size);

        // Last step: Calculate total length of SERVER_HELLO message
        *msg_buf = htons((uint16_t)(buffer - (uint8_t *)msg_buf - 2));

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;

        print_tlv(buf, buffer - buf);
        return buffer - buf;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND:
    {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */

        insert_type(&buffer, KEY_EXCHANGE_REQUEST);

        // Save pointer here for Key Exchange Request packet length which is unknown
        uint16_t *ker_len_insert = (uint16_t *)buffer;
        buffer += 2;

        // Insert self signed certificate
        memcpy(buffer, certificate, cert_size);
        buffer += cert_size;

        // Insert nonce signature tlv subpacket
        insert_type(&buffer, NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST);

        // Don't know length of signature yet so store pointer
        uint16_t *sig_len_insert = (uint16_t *)buffer;
        buffer += 2;

        // Sign client nonce stored in peer_nonce with private key and store in buffer
        size_t sig_size = sign(peer_nonce, NONCE_SIZE, buffer);
        fprintf(stderr, "SIGN SIZE %ld\n", sig_size);
        buffer += (uint16_t)sig_size;

        // Set length of signature
        *sig_len_insert = htons((uint16_t)sig_size);

        // Last step: Calculate total length of KEY_EXCHANGE_REQUEST message
        *ker_len_insert = htons((uint16_t)(buffer - (uint8_t *)ker_len_insert - 2));

        state_sec = CLIENT_FINISHED_AWAIT;
        print_tlv(buf, buffer - buf);
        return buffer - buf;
    }
    case SERVER_FINISHED_SEND:
    {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */

        insert_type(&buffer, FINISHED);
        insert_length(&buffer, 0);

        state_sec = DATA_STATE;
        return buffer - buf;
    }
    case DATA_STATE:
    {
        /* Insert Data sending logic here */
        insert_type(&buffer, DATA);

        // Save pointer here for Data packet length which is unknown
        uint16_t *data_len_insert = (uint16_t *)buffer;
        buffer += 2;

        // IV tlv
        insert_type(&buffer, INITIALIZATION_VECTOR);
        insert_length(&buffer, IV_SIZE);

        // save pointer for IV
        uint8_t *iv_insert = buffer;
        buffer += IV_SIZE;

        // Ciphertext tlv
        insert_type(&buffer, CIPHERTEXT);
        // Save pointer here for ciphertext length which is unknown
        uint16_t *cipher_len_insert = (uint16_t *)buffer;
        buffer += 2;

        // stdin data
        size_t plaintext_size =
            ((max_length - PLAINTEXT_OFFSET) / IV_SIZE) * IV_SIZE - 1;
        uint8_t plaintext[plaintext_size];
        ssize_t stdin_size = input_io(plaintext, plaintext_size);

        // Check if stdin is empty
        if (stdin_size <= 0)
            return 0;

        // Encrypt data and set length
        size_t cipher_size =
            encrypt_data(plaintext, stdin_size, iv_insert, buffer);
        *cipher_len_insert = htons((uint16_t)cipher_size);
        buffer += cipher_size;

        // Increment buffer pointer by ciphertext size

        // MAC tlv
        insert_type(&buffer, MESSAGE_AUTHENTICATION_CODE);
        insert_length(&buffer, MAC_SIZE);
        
        // HMAC digest
        uint8_t data[IV_SIZE + cipher_size];
        memcpy(data, iv_insert, IV_SIZE);
        memcpy(data + IV_SIZE, buffer - (3 + cipher_size), cipher_size);
        hmac(data, IV_SIZE + cipher_size, buffer);

        buffer += MAC_SIZE; // Increment buffer pointer by MAC size

        // Last step: Calculate total length of DATA message
        *data_len_insert = htons((uint16_t)(buffer - (uint8_t *)data_len_insert - 2));

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cipher_size);
        print_tlv(buf, buffer - buf);
        return buffer - buf;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t *buf, size_t length)
{
    // This passes it directly to standard output (working like Project 1)
    // return output_io(buf, length);

    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        /* Insert Client Hello receiving logic here */

        // Save peer nonce
        memcpy(peer_nonce, buf + 6, NONCE_SIZE);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */

        // Save server nonce
        memcpy(peer_nonce, buf + 6, NONCE_SIZE);
        fprintf(stderr, ">>> check server nonce \n");
        fprintf(stderr, "SERVER NONCE: ");
        print_hex(peer_nonce, NONCE_SIZE);
        // Implement verification logic here

        // Move the buffer pointer to the certificate packet
        buf += 6;
        buf += NONCE_SIZE;
        buf += 4;

        // Verify signature

        uint16_t peer_pub_key_len;
        print_hex(buf, 2);
        peer_pub_key_len = ntohs(*(uint16_t *)buf);
        buf += 2;

        fprintf(stderr, ">>> check peer public key length \n");
        fprintf(stderr, "PEER PUBLIC KEY LENGTH: %d\n", peer_pub_key_len);

        uint8_t *peer_pub_key = buf;
        fprintf(stderr, ">>> check peer public key \n");
        fprintf(stderr, "PEER PUBLIC KEY: ");
        print_hex(peer_pub_key, peer_pub_key_len);
        buf += peer_pub_key_len;

        // Move the buffer pointer to the signature (in certificate packet)
        buf += 1;
        uint16_t ca_sig_len;
        ca_sig_len = ntohs(*(uint16_t *)buf);
        buf += 2;

        uint8_t *ca_sig = buf;

        fprintf(stderr, ">>> check ca signature \n");
        fprintf(stderr, "CA SIGNATURE: ");
        print_hex(ca_sig, ca_sig_len);

        if (verify(peer_pub_key, peer_pub_key_len, ca_sig, ca_sig_len,
                   ec_ca_public_key) != 1)
        {
            fprintf(stderr, "Signature verification failed\n");
            exit(1);
        }
        fprintf(stderr, "Signature verification passed\n");
        load_peer_public_key(peer_pub_key, peer_pub_key_len);
        derive_secret();
        derive_keys();

        // Verification 2: Client NONCE was indeed signed by the server

        // Move the buffer pointer to the nonce signature packet
        buf += ca_sig_len;
        buf += 1;
        uint16_t nonce_sig_len = ntohs(*(uint16_t *)buf);
        buf += 2;

        uint8_t *nonce_sig = buf;

        if (verify(nonce, NONCE_SIZE, nonce_sig, nonce_sig_len,
                   ec_peer_public_key) != 1)
            exit(2);
        fprintf(stderr, "CLIENT SERVER HELLO Verification passed\n");
        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;

        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT:
    {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */
        buf += 6 + 1;
        uint16_t peer_pub_key_len = ntohs(*(uint16_t *)buf);
        fprintf(stderr, "PEER PUBLIC KEY LENGTH: %d\n", peer_pub_key_len);
        buf += 2;
        uint8_t *peer_pub_key = buf;
        print_hex(peer_pub_key, peer_pub_key_len);
        buf += peer_pub_key_len;

        // Load peer public key and perform DH and keygen
        load_peer_public_key(peer_pub_key, peer_pub_key_len);
        derive_secret();
        derive_keys();

        // verify certificate was self signed
        buf += 1;
        uint16_t cert_sig_len = ntohs(*(uint16_t *)buf);
        fprintf(stderr, "CERTIFICATE SIGNATURE LENGTH: %d\n", cert_sig_len);
        buf += 2;
        uint8_t *cert_sig = buf;
        fprintf(stderr, "CERTIFICATE SIGNATURE: ");
        print_hex(cert_sig, cert_sig_len);
        buf += cert_sig_len;

        if (verify(peer_pub_key, peer_pub_key_len, cert_sig, cert_sig_len,
                   ec_peer_public_key) != 1)
            exit(1);

        fprintf(stderr, "CERTIFICATE SIGNATURE VERIFICATION PASSED\n");
        // verification 2: server NONCE was indeed signed by the client
        buf += 1;
        uint16_t nonce_sig_len = ntohs(*(uint16_t *)buf);
        fprintf(stderr, "NONCE SIGNATURE LENGTH: %d\n", nonce_sig_len);
        buf += 2;

        uint8_t *nonce_sig = buf;
        fprintf(stderr, "NONCE SIGNATURE: ");
        print_hex(nonce_sig, nonce_sig_len);

        if (verify(nonce, NONCE_SIZE, nonce_sig, nonce_sig_len,
                   ec_peer_public_key) != 1)
            exit(2);
        fprintf(stderr, "SERVER KEY EXCHANGE REQUEST Verification passed\n");
        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT:
    {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */
        // Get IV
        buf += 6;

        uint8_t *iv = buf;
        buf += IV_SIZE;

        // Move the buffer pointer to the ciphertext
        buf += 1;

        uint16_t ciphertext_len = ntohs(*(uint16_t *)buf);
        buf += 2;

        uint8_t *ciphertext = buf;
        buf += ciphertext_len + 3;

        uint8_t *mac = buf;

        // Calculate HMAC digest
        uint8_t data[IV_SIZE + ciphertext_len];
        memcpy(data, iv, IV_SIZE);
        memcpy(data + IV_SIZE, ciphertext, ciphertext_len);

        uint8_t calculated_mac[MAC_SIZE];
        hmac(data, IV_SIZE + ciphertext_len, calculated_mac);

        // verify integrity
        if (memcmp(calculated_mac, mac, MAC_SIZE) != 0)
        {
            fprintf(stderr, "DATA integrity verification failed\n");
            exit(3);
        }

        // decrypt data
        size_t data_len = decrypt_cipher(ciphertext, ciphertext_len, iv, data);

        // Output data
        output_io(data, data_len);

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, ciphertext_len);
        break;
    }
    default:
        break;
    }
}
