//
//  PacketList.hpp
//  TEST Cyber Security
//
//  Created by Brian Vail on 11/12/17.
//  Copyright © 2017 Brian Vail. All rights reserved.
//

#include <iostream>
#include <string>
#include <stdio.h>
#include <iomanip>


#include <netinet/ip.h>


using namespace std;

#ifndef PacketList_h
#define PacketList_h

class PacketNode
{
public:
    int num;
    string sourceIp;
    string protocol;
    double flowCount;
    long startTime, lastTime;
    //long endTime;
    long totalTime;
    double rate;
    string country;
    string city;
    string ISP;
    string lattitude;
    string longitude;
    PacketNode *next;
    
};

class Packet_List
{
public:
    Packet_List(); //defualt constructor
    ~Packet_List();
    void Print();
    bool Is_Empty();
    void Insert (string sIP, string p, int fC, long sT, long lT);
    PacketNode * SearchIp(const string sIP);
    void UpdatePacketNode(PacketNode * p, long currentTime);
    PacketNode * InitializePointer();
    void Delete(PacketNode * p);
    void CalculateFlowRate();
    void PrintAttackList();
    void PrintHeader();
    void PrintAttackListNode(PacketNode *p, int i);
    int Count();
    
    
    
private:
    PacketNode *front, *back;
    
    
    
};


#endif /* PacketList_h */
