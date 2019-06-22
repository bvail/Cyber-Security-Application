//
//  PacketList.cpp
//  TEST Cyber Security
//
//  Created by Brian Vail on 11/12/17.
//  Copyright © 2017 Brian Vail. All rights reserved.
//

#include "PacketList.h"
#include <iostream>
#include <string>
#include <stdio.h>
#include <iomanip>

#include <netinet/ip.h>



using namespace std;

//defualt constructor
Packet_List:: Packet_List()
{
    //cout << "Inside default constructor\n";
    front = new PacketNode;
    front->next = 0;
    back = 0;
    
}


Packet_List::~Packet_List()
{
    //cout << "Destructor has been called\n";
    while (front != 0)
    {
        PacketNode *p = front;
        front = front->next;
        delete p;
    }
}


void Packet_List::Print()
{
    PacketNode *p = front->next;
    
    if (p == 0)
    {
        cout << "List Empty\n";
    }
    else
    {
        
        while (p != 0)
        {
            cout << p->sourceIp << " " << p->protocol << " " << p->flowCount << " ";
            cout << p->startTime << " " << endl;
            p = p->next;
            
        }

    }
}


bool Packet_List::Is_Empty()
{
    return front->next == 0;
}

void Packet_List::Insert (string sIP, string pr, int fC, long sT, long lT)
{
    PacketNode *p = new PacketNode;
    p->sourceIp = sIP;
    p->protocol = pr;
    p->flowCount = fC;
    p->startTime = sT;
    p->lastTime = lT;
    p->totalTime = 0;
    p->rate = 0;
    p->country = "/0";
    p->city = "/0";
    p->ISP = "/0";
    p->lattitude = "/0";
    p->longitude = "/0";
    p->num = 0;
    
    if (front->next == 0)
    {
        front->next = p;
        front->next->next = 0;
        back = front->next;
    }
    else
    {
        p->next = front->next;
        front->next = p;
    }
    
    
}

//returns pointer to node if found, retunrs NULL if not found
PacketNode * Packet_List::SearchIp(const string sIP)
{
    PacketNode *p = front->next;
    while (p != 0)
    {
        if (p->sourceIp == sIP)
        {
            return p;
        }
        p = p->next;
    }
    return p;
}

void Packet_List::UpdatePacketNode(PacketNode * p, long currentTime)
{
    p->flowCount = p->flowCount + 1;
    p->lastTime = currentTime;
}



PacketNode * Packet_List::InitializePointer()
{
    PacketNode *p = front->next;
    return p;
}

void Packet_List::Delete(PacketNode * p)
{
    if (p == 0)
    {
        cout << "Error: Node to delete not found\n";
    }
    else
    {
        if (p == front->next && front->next == back)
        {
            delete p;
            front->next = 0;
            back = 0;
        }
        else if (p == front->next)
        {
            front->next = p->next;
            delete p;
        }
        else
        {
            PacketNode *back_ptr = front->next;
            
            while (back_ptr != 0 && back_ptr->next != p)
            {
                back_ptr = back_ptr->next;
            }
            if (p == back)
            {
                back = back_ptr;
            }
            back_ptr->next = p->next;
            delete p;
        }
    }
}

void Packet_List::CalculateFlowRate()
{
    PacketNode *p = front->next;
    
    while (p!=0)
    {
        p->totalTime = p->lastTime - p->startTime;
        p->rate = p->flowCount / p->totalTime;
        p = p->next;
    }
}

void Packet_List::PrintAttackList()
{
    PacketNode *p = front->next;
    int i = 1;
    
    if (p == 0)
    {
        cout << "List Empty\n";
    }
    else
    {
//        cout << "No." << setw(12) <<  "Attack Type" << setw(12) << "Source IP" << setw(15);
//        cout << "Packets" << setw(8) << "Length" << setw(9) << "Rate" << setw(15) << "Country" << setw(12) << "City" << setw(5) << "ISP" << endl;
//        cout << setw(50) << "(secs)" << setw(14) << "(packets/sec)" << endl;
        
        cout << "No." << setw(12) <<  "Attack Type" << setw(12) << "Source IP" << setw(15);
        cout << "Packets" << setw(8) << "Length" << setw(9) << "Rate" << setw(15) << "Country" << setw(15) << "City" << setw(27) << "ISP" << endl;
        cout << setw(50) << "(secs)" << setw(1) << "(packets/sec)" << endl;
        
        while (p != 0)
        {
//            cout << left << setw(7) << i << setw(11) << p->protocol << setw(19) << p->sourceIp << setw(8) << p->flowCount << setw(9) << p->totalTime << setw(14) << p->rate << setw(14) << p->country << p->city << p->ISP << right << endl;
            
            cout << left << setw(7) << i << setw(11) << p->protocol << setw(19) << p->sourceIp << setw(8) << p->flowCount << setw(9) << p->totalTime << setw(13) << p->rate << setw(18) << p->country << setw(28) << p->city << p->ISP << right << endl;
            
            i++;
            p = p->next;
            
        }
        
    }

}


void Packet_List::PrintHeader()
{
    cout << "No." << setw(12) <<  "Attack Type" << setw(12) << "Source IP" << setw(15);
    cout << "Packets" << setw(8) << "Length" << setw(9) << "Rate" << setw(15) << "Country" << setw(15) << "City" << setw(27) << "ISP" << endl;
    cout << setw(50) << "(secs)" << setw(1) << "(packets/sec)" << endl;
    
}


void Packet_List::PrintAttackListNode(PacketNode *p, int i)
{
    
    if (p == 0)
    {
        cout << "List Empty\n";
    }
    else
    {
        cout << left << setw(7) << i << setw(11) << p->protocol << setw(19) << p->sourceIp << setw(8) << p->flowCount << setw(9) << p->totalTime << setw(13) << p->rate << setw(18) << p->country << setw(28) << p->city << p->ISP << right << endl;
        
    }
    
}



int Packet_List::Count()
{
    PacketNode *p = front->next;
    int i = 1;
    
    while (p!=0)
    {
        p->num = i;
        i++;
        p = p->next;
    }
    
    return i-1;
}
