@include <bits/stdc++.h>
#include <cstring>
#include <unistd.h>
#include <chrono>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
using namespace CryptoPP;
using namespace std;

// Define the server address and port
#define SERVER_ADDR "127.0.0.1"
#define PORT 8080

string privateKeyStr, publicKeyStr;
RSA::PrivateKey privateKey; 
void keys(){
 AutoSeededRandomPool rng;

    // Generate a RSA key pair
    
    privateKey.GenerateRandomWithKeySize(rng, 2048); // 2048-bit key size for example
    RSA::PublicKey publicKey(privateKey);

    // Convert keys to readable strings
    

    // Private key to string
    {
        Base64Encoder encoder(new StringSink(privateKeyStr));
        privateKey.DEREncode(encoder);
        encoder.MessageEnd();
    }

    // Public key to string
    {
        Base64Encoder encoder(new StringSink(publicKeyStr));
        publicKey.DEREncode(encoder);
        encoder.MessageEnd();
    }
   // cout<<publicKeyStr<<endl;
  }  
// Function to send signup request with username and password to the server

void* signup(void* arg) {
    int sockfd = *((int*)arg);
    char username[1024], password[1024];
    cout << "Enter userid for signup: ";
    cin >> username; // Replace cin.getline with cin >>
    cout << "Enter password for signup: ";
    cin >> password; // Replace cin.getline with cin >>
    write(sockfd, "signup", strlen("signup"));
     // Sleep for 1 second
    sleep(1);
    write(sockfd, username, strlen(username));
     // Sleep for 1 second
    sleep(1);
    write(sockfd, password, strlen(password));
    //generate keys 
    keys();
    write(sockfd,publicKeyStr.c_str(),publicKeyStr.length());
    pthread_exit(NULL);
}

// Function to send login request with username and password to the server
void* login(void* arg) {
    int sockfd = *((int*)arg);
    char username[1024], password[1024];
    
    cout << "Enter username for login: ";
    cin >> username; // Replace cin.getline with cin >>
    cout << "Enter password for login: ";
    cin >> password; // Replace cin.getline with cin >>
    write(sockfd, "login", strlen("login"));
     // Sleep for 1 second
    sleep(1);
    write(sockfd, username, strlen(username));
     // Sleep for 1 second
    sleep(1);
    write(sockfd, password, strlen(password));
    sleep(1);
    
    pthread_exit(NULL);
}
string RSAEncrypt(const RSA::PublicKey& publicKey, const std::string& plainText) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    std::string encrypted;
    StringSource(plainText, true,
        new PK_EncryptorFilter(rng, encryptor,
            new HexEncoder(
                new StringSink(encrypted)
            )
        )
    );
    return encrypted;
}

string RSADecrypt(const RSA::PrivateKey& privateKey, const std::string& cipherText) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    std::string decrypted;
    StringSource(cipherText, true,
        new HexDecoder(
            new PK_DecryptorFilter(rng, decryptor,
                new StringSink(decrypted)
            )
        )
    );
    return decrypted;
}

int flag=0;
string key;
// Function to receive server response
void* receiveResponse(void* arg) {
    int sockfd = *((int*)arg);
   while(true){
    char buffer[4096] = {0};
    int n=read(sockfd, buffer, 1024);
    if(n<=0)continue;
    buffer[n]='\0';
    string msg=buffer;
    if(msg[0]=='('){
    msg.erase(0,1);
    key=msg;
    flag=1;}
    else{
    //decrypt
    // Generate a random number generator
    string decrypted=RSADecrypt(privateKey,msg);

    cout<<decrypted<<endl;
    
    }
    }
    pthread_exit(NULL);
}

// Function to handle continuous communication with the server
void* communicateWithServer(void* arg) {
    int sockfd = *((int*)arg);
    char buffer[1024] = {0};
    while (true) {
        cout << "Enter userid  and message  to send to server: ";
        string un;
        cin>>un;
        write(sockfd, un.c_str(), un.length());
        while(flag==0){}
        //encrypt
        string message;
        cin>>message;
    
     string decodedKey;
StringSource(key, true,
        new Base64Decoder(
            new StringSink(decodedKey)
        )
    );

    // Load the decoded key into an RSA::PrivateKey object
     RSA::PublicKey publicKey;
    publicKey.Load(
        StringStore(decodedKey).Ref()
    );
   
    
    string encrypted=RSAEncrypt(publicKey,message);


         flag=0;
        write(sockfd, encrypted.c_str(), strlen(encrypted.c_str()));
        
    }
    pthread_exit(NULL);
}

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;

    // Create socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    cout << "Choose an option:" << endl;
    cout << "1. Signup" << endl;
    cout << "2. Login" << endl;
    int option;
    cin >> option;
    cin.ignore(); // Ignore newline character

    pthread_t requestThread, responseThread, communicationThread;
    if (option == 1) {
        if (pthread_create(&requestThread, NULL, signup, (void*)&sockfd) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }
    } else if (option == 2) {
        if (pthread_create(&requestThread, NULL, login, (void*)&sockfd) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }
    } else {
        cout << "Invalid option!" << endl;
        close(sockfd);
        exit(EXIT_FAILURE);
    }

 pthread_join(requestThread, NULL);
    if (pthread_create(&responseThread, NULL, receiveResponse, (void*)&sockfd) != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }
   
    if (pthread_create(&communicationThread, NULL, communicateWithServer, (void*)&sockfd) != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    pthread_join(responseThread, NULL);
    
    pthread_join(communicationThread, NULL);

    close(sockfd);
    return 0;
}
