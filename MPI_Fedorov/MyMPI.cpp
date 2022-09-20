#include <stdio.h>
#include <random>
#include <iostream>
#include <chrono>
#include <string>

#include "mpi.h"
#include "md5.h"

using namespace std;

std::string getPassword(const std::string hash, int step, int remains, std::string allowedChars, int iteration) {
    size_t startIndex = static_cast<size_t>(step) * iteration;
    size_t endIndex = startIndex + step + remains;
    size_t length = allowedChars.length();

    if (endIndex > length) {
        endIndex = length;
    }

    std::cout << "\nIteration " << iteration << " [" << startIndex << ", " << endIndex - 1 << "]" << std::endl;
    std::string result;

    for (size_t i = startIndex; i < endIndex; i++) {
        for (size_t j = 0; j < length; j++) {
            for (size_t k = 0; k < length; k++) {
                for (size_t l = 0; l < length; l++) {
                    result = "";
                    result.push_back((char)allowedChars.at(i));
                    result.push_back((char)allowedChars.at(j));
                    result.push_back((char)allowedChars.at(k));
                    result.push_back((char)allowedChars.at(l));
                    std::string anotherHash = md5(result);

                    if (hash.compare(anotherHash) == 0) {
                        return result;
                    }
                }
            }
        }
    }

    return "????";
}

int main() {
    int tag = 0;
    int nProcesses, rank;
    std::string allowedChars("1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM");
    size_t allowedCharsCount = allowedChars.length(); // 62
    int allowedLength = 4;
    std::string password;

    auto start = std::chrono::system_clock::now();

    MPI_Init(NULL, NULL);
    MPI_Status status;
    MPI_Comm comm = MPI_COMM_WORLD;
    MPI_Comm_size(comm, &nProcesses);
    MPI_Comm_rank(comm, &rank);

    char buf[34];
    char pwd[5];

    if (rank == 0) {
        std::random_device rd;
        std::default_random_engine eng(rd());
        std::uniform_real_distribution<> getIndex(0, (int)allowedChars.length());

        for (int i = 0; i < allowedLength; ++i) {
            password += allowedChars.at((int)getIndex(eng));
        }

        const std::string md5hash = md5(password);
        std::cout << "Password: " << password << std::endl;
        std::cout << "MD5 hash: " << md5hash << std::endl;

        for (int i = 1; i < nProcesses; i++) {
            std::string tempMd5hash = md5hash;
            tempMd5hash += std::to_string(i);
            strcpy_s(buf, tempMd5hash.c_str());
            MPI_Send(buf, (int) tempMd5hash.size() + 1, MPI_CHAR, i, tag, comm);
        }

        MPI_Recv(pwd, allowedLength + 1, MPI_CHAR, MPI_ANY_SOURCE, tag, comm, &status);
        std::cout << "root recieved password: ";
        std::string result = std::string(pwd);
        std::cout << result << std::endl;

        if (password.compare(result) == 0) {
            std::cout << "Result: " << result << std::endl;
            auto end = std::chrono::system_clock::now();
            auto elapsed_nanoseconds = (end - start).count();
            std::cout << "Time spent, ns: " << elapsed_nanoseconds << std::endl;
        } else {
            std::cerr << "Unable to decode password" << std::endl;
        }

        MPI_Abort(comm, 1);
    } else {
        size_t step = allowedCharsCount / (nProcesses == 1 ? 1 : (static_cast<unsigned long long>(nProcesses) - 1));
        int recvSize;
        int flag = 1;

        MPI_Iprobe(0, tag, comm, &flag, &status);
        std::cout << rank << "   probe   success" << std::endl;
        MPI_Get_count(&status, MPI_CHAR, &recvSize);
        MPI_Recv(buf, 40, MPI_CHAR, 0, tag, comm, &status);

        std::string hash = "";

        for (size_t i = 0; i < 32; i++) {
            hash += buf[i];
        }

        int iteration = atoi(&buf[32]);
        int remains = (rank == nProcesses - 1) ? (int) allowedCharsCount % nProcesses : 0;
        std::string passwordToSend = getPassword(hash, (int)step, remains, allowedChars, iteration - 1);

        if (passwordToSend.compare("????") != 0) {
            //MPI_Isend(passwordToSend.c_str(), allowedLength, MPI_CHAR, 0, tag, comm, &requests[rank - 1]);
            strcpy_s(pwd, passwordToSend.c_str());
            pwd[4] = 0;
            MPI_Send(pwd, allowedLength + 1, MPI_CHAR, 0, tag, comm);
            std::cout << rank << " sent \"" << passwordToSend.c_str() << "\"" << std::endl;
        }
    }

    std::cout << rank << " finalizing" << std::endl;
    MPI_Finalize();
}
