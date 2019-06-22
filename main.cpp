//
//  main.cpp
//  TEST Cyber Security
//
//  Created by Brian Vail on 10/30/17.
//  Copyright © 2017 Brian Vail. All rights reserved.
//


#include <iostream>
#include <string>
#include <pcap.h>
#include "PacketList.h"
#include <iomanip>
#include <fstream>
#include <curl/curl.h>
#include <unistd.h>


#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

using namespace std;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void FinalFlowCheck();

//Finds IP information using address call
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
void GeoLocateIP();

//Finds IP information using a csv database
string find_GeoIP(string, PacketNode  *p);
bool IP_in_range(string, string, string);
void ID_lookup(string, PacketNode  *p);
void GeoLocateDB();

//User selection GeoMapping
void GeoMapping(int);

//global variable for packet number, time of last packet, time a node has been in flow
int packet_count = 0;
long currentTime;
long timeInFlow = 0;

const long flowThreshold = 300;
const int packetThreshold = 100;

Packet_List TCP_List;
Packet_List ICMP_List;
Packet_List UDP_List;
Packet_List Attack_List;



int main()
{
    cout << "\nWelcome to DDoS Analysis Program\n\n";
    
    
    //string file = "/Users/brianvail/Desktop/FAU Classes/Cyber Security/14.pcap";
    
    //string file = "/Users/brianvail/Desktop/14.pcap Segmented Files/100000_14_00000_20131130190000.pcap";
    
    //user entered file
    
    string file = "/Users/brianvail/Desktop/";
    string name;
    cout << "Place file on desktop and enter the pcap file name: ";
    cin >> name;
    file = file + name;
    

    
    
    
    char errbuff[PCAP_ERRBUF_SIZE];
    
    //opens packet capture file OR stores error in errbuff and exits program
    pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);
    
    if (pcap == NULL)
    {
        cout << "pcap_open_live() failed: " << errbuff << endl;
        return 1;
    }
    
    cout << "Reading pcap file..." << endl;
    cout << "Packets Analyzed (in millions): ";

    //begins packet processing loop
    if (pcap_loop(pcap, 0, packetHandler, NULL) < 0)
    {
        cout << "pcap_loop() failed: " << pcap_geterr(pcap);
    }
    
    
    cout << "Capture Complete\n\n";
    cout << "Flow Analysis...";
    
    
    FinalFlowCheck();
    
   
    Attack_List.CalculateFlowRate();
  
    cout << "Complete\n\n";
    
    //searches DB for IP address, adds country, city and isp to attack list
    
    cout << "Searching GeoLocation Database...\n\n";
    
    //GeoLocateDB();
    
    GeoLocateIP();

    cout << "\nComplete.\n\n";
    
    
    //goes into user selection mapping
    int i = Attack_List.Count();
    
    GeoMapping(i);
    
    cout << "End of Program.\n";

    return 0;
    
}




void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    
    const struct ether_header* ethernetHeader;
    const struct ip* ipHeader;
    char srcIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];
    string sourceIp, destinationIp;
    

    const struct tcphdr* tcpHeader;
    const struct icmp* icmpHeader;

    
    string protocolType;
    
  
    ++packet_count;
    if (packet_count % 10000000  == 0)
    {
        cout << packet_count/1000000 << "... ";
        //cout << packet_count/1000000 << " million packets analyzed\n";
    }
    
    //parses out the source and destination IP of each packet
    ethernetHeader = (struct ether_header*)packet;
 
    if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP)
    {
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
        
        //cout << packet_count << " : " << srcIp << "-->" << destIp << endl;
        
        //converts srcIP and destIP to strings
        sourceIp = srcIp;
        destinationIp = destIp;
 
        
        
        
        //reads protocol type
        //if TCP protocol and the packet is Syn/Ack the packet is labeled for future flow analysis
        //note: 4608 = SYN/ACK packet for TCP attack
        if (ipHeader->ip_p == IPPROTO_TCP)
        {
            
            tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            
            
           if (ntohs(tcpHeader->th_flags) == 4608)
           {
            protocolType = "TCP";
           }
            
       }
        //if ICMP protocol, reads packet type and is labeled for future flow analysis
        //note: 2048 = type 8 echo (ping) request for ICMP attack
        //note:m768 = type 3 destination unreachable for UDP attack
       else if (ipHeader->ip_p == IPPROTO_ICMP)
       {
           
           icmpHeader = (icmp*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
           
           if (ntohs(icmpHeader->icmp_type) == 2048)
           {
               protocolType = "ICMP";
           }
           else if (ntohs(icmpHeader->icmp_type) == 768)
           {
               protocolType = "UDP";
           }
       }
       else{
           //cout << "It's neither\n";
           protocolType = "\0";
       }
        
        
        //reads Epoch time of packet
        currentTime = pkthdr->ts.tv_sec;
        
        
    
        //Adds packet to protocol specific list if no matching source IP already in list
        //Or increase flow count for matching source IP
        if (protocolType == "TCP")
        {
            PacketNode *p = TCP_List.SearchIp(sourceIp);
            if (p == 0)
            {
                 TCP_List.Insert(sourceIp, protocolType, 1, currentTime, currentTime);
            }
            else if (p != 0)
            {
                TCP_List.UpdatePacketNode(p, currentTime);
            }
            else
            {
                cout << "Error: TCP IP neither found nor not found\n";
            }
        }
        else if (protocolType == "ICMP")
        {
            PacketNode *p = ICMP_List.SearchIp(sourceIp);
            if (p == 0)
            {
                ICMP_List.Insert(sourceIp, protocolType, 1, currentTime, currentTime);
            }
            else if (p != 0)
            {
                ICMP_List.UpdatePacketNode(p, currentTime);
            }
            else
            {
                cout << "Error: ICMP IP neither found nor not found\n";
            }
        }
        else if (protocolType == "UDP")
        {
            PacketNode *p = UDP_List.SearchIp(sourceIp);
            if (p == 0)
            {
                UDP_List.Insert(sourceIp, protocolType, 1, currentTime, currentTime);
            }
            else if (p != 0)
            {
                UDP_List.UpdatePacketNode(p, currentTime);
            }
            else
            {
                cout << "Error: UDP IP neither found nor not found\n";
            }
        }
        else
        {
            //cout << "Not relevant protocol\n";
            
        }
        
        
        
        //Traverses TCP List, check time since last packet arrival with same source IP address
        //if flow time is past time threshold and sufficient packets, add to attack list and delete node
        //if flow time is past time threshold and insufficient packets, deletes node
        //or moves onto next node
        
        
        
        //update lists every 1000 packets (approx 1 second)
        if ((packet_count % 1000  == 0))
        {
            PacketNode  *p = TCP_List.InitializePointer();
            
            while (p != 0)
            {
                timeInFlow = currentTime - p->lastTime;
                
                if (timeInFlow > flowThreshold)
                {
                    if (p->flowCount >= packetThreshold && (p->lastTime - p->startTime >= 60))
                    {
                        Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
                        PacketNode *q = p;
                        p = p->next;
                        TCP_List.Delete(q);
                    }
                    else
                    {
                        PacketNode *q = p;
                        p = p->next;
                        TCP_List.Delete(q);
                    }
                }
                else
                {
                    p = p->next;
                }
            }
            
            
            
            //Repeat for ICMP List
            p = ICMP_List.InitializePointer();
            
            while (p != 0)
            {
                timeInFlow = currentTime - p->lastTime;
                
                if (timeInFlow > flowThreshold)
                {
                    if (p->flowCount >= packetThreshold && (p->lastTime - p->startTime >= 60))
                    {
                        Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
                        PacketNode *q = p;
                        p = p->next;
                        ICMP_List.Delete(q);
                    }
                    else
                    {
                        PacketNode *q = p;
                        p = p->next;
                        ICMP_List.Delete(q);
                    }
                }
                else
                {
                    p = p->next;
                }
            }
            
            
            
            //Repaet for UDP List
            p = UDP_List.InitializePointer();
            
            while (p != 0)
            {
                timeInFlow = currentTime - p->lastTime;
                
                if (timeInFlow > flowThreshold)
                {
                    if (p->flowCount >= packetThreshold && (p->lastTime - p->startTime >= 60))
                    {
                        Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
                        PacketNode *q = p;
                        p = p->next;
                        UDP_List.Delete(q);
                    }
                    else
                    {
                        PacketNode *q = p;
                        p = p->next;
                        UDP_List.Delete(q);
                    }
                }
                else
                {
                    p = p->next;
                }
            }

        
            
        }
        

        
    }
}


//checks each list one last time to find any more last nodes that qualify as an attack
//ddos attack if node has been in flow more than 60 secs and has sufficient packets
void FinalFlowCheck()
{
    
    //For TCP List
    PacketNode  *p = TCP_List.InitializePointer();
    
    while (p != 0)
    {
        timeInFlow = p->lastTime - p->startTime;
        
       
        if (timeInFlow >= 60 && (p->flowCount >= packetThreshold))
        {
            Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
            PacketNode *q = p;
            p = p->next;
            TCP_List.Delete(q);
      
        }
        else
        {
            p = p->next;
        }
    }
    
    //Repeat for ICMP List
    p = ICMP_List.InitializePointer();
    
    while (p != 0)
    {
        timeInFlow = p->lastTime - p->startTime;
        
        if (timeInFlow >= 60 && (p->flowCount >= packetThreshold))
        {
            Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
            PacketNode *q = p;
            p = p->next;
            ICMP_List.Delete(q);
        }
        else
        {
            p = p->next;
        }
    }
    
    //Repeat for UDP List
    p = UDP_List.InitializePointer();
    
    while (p != 0)
    {
        timeInFlow = p->lastTime - p->startTime;
        
        if (timeInFlow >= 60 && (p->flowCount >= packetThreshold))
        {
            Attack_List.Insert(p->sourceIp, p->protocol, p->flowCount, p->startTime, p->lastTime);
            PacketNode *q = p;
            p = p->next;
            UDP_List.Delete(q);
        }
        else
        {
            p = p->next;
        }
    }
    
    
}

//******************
//FIND IP INFORMATION CALLING ADDRESS
//******************
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


void GeoLocateIP()
{
    PacketNode  *p = Attack_List.InitializePointer();
    
    string address;
    int c = 1;
    
    Attack_List.PrintHeader();

    while (p != 0)
        
    {
        
        //cout << "1\n";
        
        CURL *curl;
        CURLcode res;
        string readBuffer;
        
        //cout << "2\n";
        
        address = "http://ip-api.com/json/";
        address += p->sourceIp;
        
        //cout << "3\n";
        
        //opens url, reads IP information, saves to string (readBuffer)
        curl = curl_easy_init();
        
        //cout << "3\n";
        
        if(curl)
        {
            curl_easy_setopt(curl, CURLOPT_URL, address.c_str());
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);
        }

        //cout << "4\n";
        
        
        
        //Checks for return error, if error skips this node
        int a = 0;
        int b = 0;
        string test;
        
        while (readBuffer[a] != '"') { a++; }
        a++;
        b = a;
        while (readBuffer[a] != '"') { a++; }
        for ( ; b < a; b++)
        {
            test += readBuffer[b];
        }

        //cout << "5\n";
        
        if (test != "as")
        {
            //cout << "6\n";
            
            p->country = "Unable to retrieve geolocation information.";
            Attack_List.PrintAttackListNode(p, c);
            c++;
    
            p = p->next;
            
        }
        else
        {
         
         
            //cout << "7\n";
            
            //Parses readBuffer string into city, country, ISP, lattitude and longitude
            string city, country, ISP, lat, lon;
            int i = 0;
            int j = 0;
            
            //Parses city name
            while (readBuffer[i] != ':') { i++; }
            i++;
            while (readBuffer[i] != ':') { i++; }
            i = i+2;
            j = i;
            while (readBuffer[i] != '"') { i++;}
            for ( ; j < i; j++)
            {
                city += readBuffer[j];
            }
            
            //Parses country name
            while (readBuffer[i] != ':') { i++; }
            i = i+2;
            j = i;
            while (readBuffer[i] != '"') { i++;}
            for ( ; j < i; j++)
            {
                country += readBuffer[j];
            }
            
            //Parses ISP
            while (readBuffer[i] != ':') { i++; }
            i++;
            while (readBuffer[i] != ':') { i++; }
            i = i+2;
            j = i;
            while (readBuffer[i] != '"') { i++;}
            for ( ; j < i; j++)
            {
                ISP += readBuffer[j];
            }
            
            //Parses lattitude
            while (readBuffer[i] != ':') { i++; }
            i++;
            j = i;
            while (readBuffer[i] != ',') { i++;}
            for ( ; j < i; j++)
            {
                lat += readBuffer[j];
            }
            
            //Parses longitude
            while (readBuffer[i] != ':') { i++; }
            i++;
            j = i;
            while (readBuffer[i] != ',') { i++;}
            for ( ; j < i; j++)
            {
                lon += readBuffer[j];
            }
            
            
            //Saved IP info into Attack Node
            p->city = city;
            p->country = country;
            p->ISP = ISP;
            p->lattitude = lat;
            p->longitude = lon;
            
            Attack_List.PrintAttackListNode(p, c);
            c++;
            
            p = p->next;
        }
        
        usleep(400000);
        
    }
    return;

    
    
}










//******************
//FIND IP INFORMATION USING CSV DATABASE
//******************

string find_GeoIP(string sourceIP, PacketNode  *p)
{
    //OPENING CSV FILE
    //cout << "OPENING CSV FILE\n\n";
    
    ifstream geoIP("/Users/brianvail/Desktop/GeoLite2-City-CSV_20171107/GeoLite2-City-Blocks-IPv4.csv");
    if (!geoIP.is_open()) { cout << "Error opening GeoIP file\n";}
    
    string network1, network2;
    string geoname_id1, geoname_id2;
    string lat1, lat2;
    string lon1, lon2;
    string junk;
    
    //searches database for IP match
    //returns geoID if found
    getline(geoIP, junk);
    getline(geoIP, network1, ',');
    getline(geoIP, geoname_id1, ',');
    for (int i = 0; i < 5; i++)
    {
        getline(geoIP, junk, ',');
    }
    getline(geoIP, lat1, ',');
    getline(geoIP, lon1, ',');
    getline (geoIP, junk);
    
    
    while (geoIP.good())
    {
        getline(geoIP, network2, ',');
        getline(geoIP, geoname_id2, ',');
        for (int i = 0; i < 5; i++)
        {
            getline(geoIP, junk, ',');
        }
        getline(geoIP, lat2, ',');
        getline(geoIP, lon2, ',');
        getline (geoIP, junk);
        
        if (IP_in_range(sourceIP, network1, network2))
        {
            p->lattitude = lat1;
            p->longitude = lon1;
            geoIP.close();
            return geoname_id1;
        }
        
        network1 = network2;
        geoname_id1 = geoname_id2;
        lat1 = lat2;
        lon1 = lon2;
        
    }

    geoIP.close();
    return "0";
}



bool IP_in_range(string IP_string, string CIDR_string1, string CIDR_string2)
{
    string IP_bit1, IP_bit2, IP_bit3, IP_bit4;
    int a = 0;
    int b = 0;
    
    
    string CIDR1_bit1, CIDR1_bit2, CIDR1_bit3, CIDR1_bit4;
    int c = 0;
    int d = 0;
    
    
    string CIDR2_bit1, CIDR2_bit2, CIDR2_bit3, CIDR2_bit4;
    int e = 0;
    int f = 0;
    
    
    
    //parses first octent of our IP address
    while (IP_string[a] != '.') { a++;}
    for ( ; b < a; b++)
    {
        IP_bit1 += IP_string[b];
    }
    
    
    //pasrses first octet of the lower CIDR address range
    while (CIDR_string1[c] != '.') { c++; }
    for ( ; d < c; d++)
    {
        CIDR1_bit1 += CIDR_string1[d];
    }
    
    //parses first octet of the upper CIDR address range
    while (CIDR_string2[e] != '.') { e++; }
    for ( ; f < e; f++)
    {
        CIDR2_bit1 += CIDR_string2[f];
    }
    
    
    if (IP_bit1 == CIDR1_bit1)
    {
        //convert octets from string to ints for comparison
        int iIP_bit1 = atoi(IP_bit1.c_str());
        int iCIDR1_bit1 = atoi(CIDR1_bit1.c_str());
        int iCIDR2_bit1 = atoi(CIDR2_bit1.c_str());
        
        //if IP between first octet of lower CIDR and first octet of upper CIDR, return true
        if ((iCIDR1_bit1 <= iIP_bit1) && (iIP_bit1 < iCIDR2_bit1))
        {
            return true;
        }
        
        //parses second octent of our IP address
        a += 1;
        b += 1;
        while (IP_string[a] != '.') { a++; }
        for ( ; b < a; b++)
        {
            IP_bit2 += IP_string[b];
        }
        
        
        //pasrses second octet of the lower CIDR address range
        c += 1;
        d += 1;
        while (CIDR_string1[c] != '.') { c++; }
        for ( ; d < c; d++)
        {
            CIDR1_bit2 += CIDR_string1[d];
        }
        
        
        //pasrses second octet of the upper CIDR address range
        e += 1;
        f += 1;
        while (CIDR_string2[e] != '.') { e++; }
        for ( ; f < e; f++)
        {
            CIDR2_bit2 += CIDR_string2[f];
        }
        
        
        if (IP_bit2 == CIDR1_bit2)
        {
            //convert octets from string to ints for comparison
            int iIP_bit2 = atoi(IP_bit2.c_str());
            int iCIDR1_bit2 = atoi(CIDR1_bit2.c_str());
            int iCIDR2_bit2 = atoi(CIDR2_bit2.c_str());
            
            
            //if IP between second octet of lower CIDR and second octet of upper CIDR, return true
            if ((iCIDR1_bit2 <= iIP_bit2) && (iIP_bit2 < iCIDR2_bit2))
            {
                return true;
            }
            
            //parses third octet of our IP address
            a += 1;
            b += 1;
            while (IP_string[a] != '.') { a++; }
            for ( ; b < a; b++)
            {
                IP_bit3 += IP_string[b];
            }
            
            
            //pasrses third octet of the lower CIDR address range
            c += 1;
            d += 1;
            while (CIDR_string1[c] != '.') { c++; }
            for ( ; d < c; d++)
            {
                CIDR1_bit3 += CIDR_string1[d];
            }
            
            //pasrses third octet of the upper CIDR address range
            e += 1;
            f += 1;
            while (CIDR_string2[e] != '.') { e++; }
            for ( ; f < e; f++)
            {
                CIDR2_bit3 += CIDR_string2[f];
            }
            
            
            if (IP_bit3 == CIDR1_bit3)
            {
                
                //convert octets from string to ints for comparison
                int iIP_bit3 = atoi(IP_bit3.c_str());
                int iCIDR1_bit3 = atoi(CIDR1_bit3.c_str());
                int iCIDR2_bit3 = atoi(CIDR2_bit3.c_str());
                
                //if IP between third octet of lower CIDR and third octet of upper CIDR, return true
                if ((iCIDR1_bit3 <= iIP_bit3) && (iIP_bit3 < iCIDR2_bit3))
                {
                    return true;
                }
                
                
                //parses fourth octet of our IP address
                a += 1;
                b += 1;
                while (IP_string[a] != '.') { a++; }
                for ( ; b < a; b++)
                {
                    IP_bit4 += IP_string[b];
                }
                
                //pasrses fourth octet of the lower CIDR address range
                c += 1;
                d += 1;
                while (CIDR_string1[c] != '.') { c++; }
                for ( ; d < c; d++)
                {
                    CIDR1_bit4 += CIDR_string1[d];
                }
                
                //pasrses fourth octet of the upper CIDR address range
                e += 1;
                f += 1;
                while (CIDR_string2[e] != '.') { e++; }
                for ( ; f < e; f++)
                {
                    CIDR2_bit4 += CIDR_string2[f];
                }
                
                
                if (IP_bit4 == CIDR1_bit4)
                {
                    
                    //convert octets from string to ints for comparison
                    int iIP_bit4 = atoi(IP_bit4.c_str());
                    int iCIDR1_bit4 = atoi(CIDR1_bit4.c_str());
                    int iCIDR2_bit4 = atoi(CIDR2_bit4.c_str());
                    
                    
                    //if IP between fourth octet of lower CIDR and third octet of upper CIDR, return true
                    if ((iCIDR1_bit4 <= iIP_bit4) && (iIP_bit4 < iCIDR2_bit4))
                    {
                        return true;
                    }
                    
                    
                }
                
                
            }
            
            
        }
        
        
    }
    
    
    return false;
    
}


void ID_lookup(string geoID, PacketNode  *p)
{
    //OPENING CSV FILE
    //cout << "OPENING CSV FILE\n\n";
    
    ifstream geoLocation("/Users/brianvail/Desktop/GeoLite2-City-CSV_20171107/GeoLite2-City-Locations-en.csv");
    if (!geoLocation.is_open()) { cout << "Error opening GeoIP file\n";}
    
    string ID;
    string country;
    string city;
    string junk;
    
    //searches database for ID match
    //inserts country and city into attack list if found
    getline(geoLocation, junk);
    while (geoLocation.good())
    {
        getline(geoLocation, ID, ',');
        
        for (int i = 0; i < 4; i++)
        {
            getline(geoLocation, junk, ',');
        }
        
        getline(geoLocation, country, ',');
        
        for (int i = 0; i < 4; i++)
        {
            getline(geoLocation, junk, ',');
        }
        
        getline(geoLocation, city, ',');
        
        getline (geoLocation, junk);
        
        if (ID == geoID)
        {
            geoLocation.close();
            p->country = country;
            p->city = city;
            return;
        }
        
    }
    
    geoLocation.close();
    cout << "ID not found\n";
    
    

}


void GeoLocateDB()
{
    PacketNode  *p = Attack_List.InitializePointer();
    string geoID;
    
    Attack_List.PrintHeader();
    int i = 1;
    
    while (p != 0)

    {
        geoID = find_GeoIP(p->sourceIp, p);
        ID_lookup(geoID, p);
        
        Attack_List.PrintAttackListNode(p, i);
        i++;
        
        p = p->next;
        
    }
    return;
    
}


//User selection GeoMapping
void GeoMapping(int i)
{
    int m;
    //int x = 0;
    
    cout << "Enter Attack No. (1 - " << i << ") to Map or '0' to exit: ";
    while(!(cin >> m)){
        cin.clear();
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        cout << "Invalid input. Enter valid Attack No.: ";
    }
    
    while (m != 0)
    {
        if ((m >=1) && (m <= i))
        {
            PacketNode  *p = Attack_List.InitializePointer();
            
            while (p->num != m)
            {
                p = p->next;
            }
            
            string s;
            string s0 = "https://maps.googleapis.com/maps/api/staticmap?center=Brooklyn+Bridge,New+York,NY\\&zoom=1\\&size=1200x600\\&maptype=roadmap\\&markers=color:blue%7Clabel:S%7C";
            string s1 = p->lattitude;
            string s2 = ",";
            string s3 = p->longitude;
            
            s = s + s0 + s1 + s2 + s3;
            system(("open " + s).c_str());
            
            cout << "\nYou selected Attack No. " << p->num << " at " << p->city << ", " << p->country << ": Attack Type: " << p->protocol << endl;
            
            cout << "\nEnter Attack No. (1 - " << i << ") to Map or '0' to exit: ";
            while(!(cin >> m))
            {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input. Enter valid Attack No.: ";
            }
            
            
        }
        else
        {
            cout << "Invalid Input. Enter valid Attack No.: ";
            while(!(cin >> m))
            {
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                cout << "Invalid input. Enter valid Attack No.: ";
            }
        }
        
        
    }
}
