#include <bits/stdc++.h>
#include <cstring>
#include <map>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>

using namespace std;

// Define the port number
#define PORT 8080

// Structure to store client information
struct ClientInfo {
    int sockfd;
    string username;
    string hashedPassword;
    string salt;
    string publickey;
};

// Map to store client information
map<string, ClientInfo> clients;
map<string,int>fds;

// Function to generate a random salt
string generateSalt() {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::byte tempSalt[16];
    prng.GenerateBlock(tempSalt, sizeof(tempSalt));
    string encoded;
    CryptoPP::StringSource(tempSalt, sizeof(tempSalt), true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    return encoded;
}

// Function to hash a password with salt
string hashPassword(const string& password, const string& salt) {
    CryptoPP::SHA256 hash;
    string hashed;
    CryptoPP::StringSource(password + salt, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(hashed)
            )
        )
    );
    return hashed;
}

// Function to handle client signup
bool signupClient(const string& username, const string& password,const string& publicKeyBuffer) {
    if (clients.find(username) == clients.end()) {
        string salt = generateSalt();
        string hashed = hashPassword(password, salt);
        ClientInfo client;
        client.username = username;
        client.hashedPassword = hashed;
        client.salt = salt;
        client.publickey=publicKeyBuffer;
        clients[username] = client;
        return true;
    }
    return false;
}

// Function to handle client authentication
bool authenticateClient(const string& username, const string& password) {
    if (clients.find(username) != clients.end()) {
        ClientInfo& client = clients[username];
        string hashed = hashPassword(password, client.salt);
        return hashed == client.hashedPassword;
    }
    return false;
}

// Function to handle client requests
void* handleClient(void* arg) {
    int new_socket = *((int*)arg);
    char buffer[1024] = {0};
    string username, password,choice;
    int n=read(new_socket, buffer, 1024);
    buffer[n]='\0';
    choice=buffer;
    
    memset(buffer, '\0', sizeof(buffer)); // Clear buffer
      n=read(new_socket, buffer, 1024);
    buffer[n]='\0';
    username = buffer;
   
    memset(buffer, '\0', sizeof(buffer)); // Clear buffer
        n=read(new_socket, buffer, 1024);
    buffer[n]='\0';
    password = buffer;
     
     int b=0;
     if (choice=="signup")  {
     b=1;
      string publicKeyBuffer;
    char tempBuffer[4096]; // Temporary buffer for reading
    ssize_t bytesRead;
    while ((bytesRead = read(new_socket, tempBuffer, sizeof(tempBuffer))) > 0) {
        publicKeyBuffer.append(tempBuffer, bytesRead);
        if (bytesRead < sizeof(tempBuffer)) break; // End of message
    }
   // cout<<publicKeyBuffer<<endl;
    bool k=signupClient(username,password,publicKeyBuffer);
    fds[username]=new_socket;
    
    
     
     
       // write(new_socket, "Signup successful!", strlen("Signup successful!"));
        
    } else if (choice=="login"&&authenticateClient(username, password)) {
       // write(new_socket, "Login successful!", strlen("Login successful!"));
        b=1;
       
    } else {
       // write(new_socket, "Invalid credentials!", strlen("Invalid credentials!"));
    }
   
     while (true) {
            // Simulate continuous communication
            string un;
            memset(buffer, '\0', sizeof(buffer));
            n=read(new_socket, buffer, 1024);
            
    buffer[n]='\0';
    un=buffer;
   
    memset(buffer, '\0', sizeof(buffer));
    string key="(";
    string key2=clients[un].publickey;
    key+=key2;
    write(new_socket,key.c_str(),key.length());
     n=read(new_socket, buffer, 1024);
    buffer[n]='\0';
            string message ;
     
            message = buffer;
            cout<<"msg from "<<un<<" : "<<message<<endl;
            write(fds[un], message.c_str(), strlen(message.c_str()));
        }
        
    close(new_socket);
    pthread_exit(NULL);
}

// Main function to start the server
int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    
    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                                                  &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Bind the socket to the address and port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    
    // Start listening for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
   
    // Accept incoming connections and handle them using pthreads
    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            exit(EXIT_FAILURE);
        }
        
        pthread_t thread;
        if (pthread_create(&thread, NULL, handleClient, (void*)&new_socket) != 0) {
            perror("Thread creation failed");
            exit(EXIT_FAILURE);
        }
        
    }
    
    return 0;
}
