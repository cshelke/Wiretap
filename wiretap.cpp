#include<stdio.h>
#include<iostream>
#include<string.h>
#include<ctype.h>
#include<unistd.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>
#include "if_ether.h"
#include "udp.h"
#include "ether.h"
#include "ip.h"
#include "tcp.h"
#include "ip_icmp.h"
#include "template_structures.h"
#include<map>
#include<cstdlib>
#include<cstring>
#include<cstdio>
#include<sstream>

#define SIZE_ETHERNET 14;
using namespace std;

//map<string,int> eth_dest;
typedef struct {
	uint8_t type;	
	uint8_t size;
} t_option;


int i = 6;
int tcp_count=0;
int ipv4_count=0;
std::stringstream stream;
int insert_count = 0;
string ETH_P_ARP_("0x0806");
string ETH_P_IP_("0x0800");
unsigned short iphdrlen;
const char* fname;
int count = 0;
int curg = 0;
int cack = 0;
int cpsh = 0;
int crst = 0;
int csyn = 0;
int cfin = 0;

class Wiretap{

public: //netinet/ip_icmp.h
	time_t start_time;
	time_t end_time;
	int packet_count;
	int total_pkt_size;
	int avg_size;
	int min_size;
	int max_size;
	pcap_t * pcap_handle; 	
	map<string,int> eth_src;
	map<string,int> eth_dest;
	map<string,int> n_protocols; //network layer protocols
	map<string,int> ip_source;
	map<string,int> ip_dest;
	map<unsigned int,int> time_to_live;
	map<string,int> arp_mac;
	map<string,int> tl_protocols;
	map<unsigned int,int> tcp_src_port;
	map<unsigned int,int> tcp_dest_port;
	map<unsigned int,int> udp_src_port;
        map<unsigned int,int> udp_dest_port;
	map<unsigned int,int> icmp_types;
	map<unsigned int,int> icmp_codes;
	map<unsigned int,int> options;
	int tcp_count;
	int udp_count;
	int icmp_count;

	void ttl_to_map(unsigned int, map<unsigned int, int> &);
	void open_file();
	void ethernet_addr(const u_char*);
	void print_summary();
	char * modify_eth(unsigned char[]);
	void add_to_map(char *,map<string, int> &);
	void tlayer_to_map(int , map<string, int> &);


};
Wiretap wtap;

string convert_i_to_s(int x){
	stringstream i_to_s;
	string str1;
	str1.clear();
	i_to_s << x;
	str1 = i_to_s.str();
	return str1;
}


char * Wiretap :: modify_eth(unsigned char ethernet[])
{
	//cout<<" value of ethernet : "<<ethernet<<endl;
	char *temp1 = (char *)calloc(12, sizeof(char));;
	char *temp2 = (char *)calloc(12, sizeof(char));
	char *temp3 = (char*)calloc(17 , sizeof(char));
	int i = 0;
	for(i=0;i<6;i++)
	{

		sprintf(temp1,"%02X" , ethernet[i]);
		strcat(temp2 , temp1);
	}
	int j = 1;
	temp3[0]=temp2[0];
	for(i=1;i<12;i++){
		if(i%2!=0){
			temp3[j] = temp2[i];
			j++;
		}
		else{
			temp3[j] = ':';
			j++;
			temp3[j] = temp2[i];
			j++;
		}
		temp3[j]='\0';

	}
	
	return temp3;
}


void Wiretap :: ttl_to_map(unsigned int ttl, map<unsigned int, int> &temp_map)
{


	std::pair<std::map<unsigned int,int>::iterator,bool> ret;
	ret = temp_map.insert (std::pair<unsigned int,int>(ttl,1));

	if(ret.second == false)
	{
		ret.first->second = ret.first->second+1;
	}

}


void Wiretap :: add_to_map(char * add, map<string, int> &temp_map)
{


	string temp = add;
	std::pair<std::map<string,int>::iterator,bool> ret;
	ret = temp_map.insert (std::pair<string,int>(temp,1));

	if(ret.second == false)
	{
		ret.first->second = ret.first->second+1;
	}
	temp.clear();

}

void Wiretap :: tlayer_to_map(int pno, map<string, int> &temp_map)
{
	//pno -> protocol no.
	string proto;

	switch(pno)
	{
	 	case 1:  //ICMP Protocol
	            	proto="ICMP";
	            	break;
	        case 6:  //TCP Protocol
	        	proto="TCP";
	            	break;
	        case 17: //UDP Protocol
	        	proto="UDP";
	            	break;

	        default: //Some Other Protocol like ARP etc.
	        	proto = convert_i_to_s(pno);
	            	break;
	}
	std::pair<std::map<string,int>::iterator,bool> ret;
	ret = temp_map.insert (std::pair<string,int>(proto,1));

	if(ret.second == false)
	{
		ret.first->second = ret.first->second+1;
	}
	proto.clear();

}


void Wiretap :: ethernet_addr(const u_char *packet)
{

	struct ethhdr *ethernet = (struct ethhdr*)packet;
	struct ip *ip = (struct ip*)(packet + sizeof(struct ethhdr));
	struct arphd *arp = (struct arphd*)(packet + sizeof(struct ethhdr));
	char *source_add = (char*)calloc(17,sizeof(char));
	char *dest_add =  (char*)calloc(17,sizeof(char));
	char *arp_hware_add = (char*)malloc(sizeof(char)*60);
	source_add= modify_eth(ethernet->h_source);
	dest_add = modify_eth(ethernet->h_dest);
	
	wtap.add_to_map(source_add, eth_src);
	wtap.add_to_map(dest_add, eth_dest);

	std::string result;
	std::stringstream ss;
	ss << "0x0"<<std::hex <<ntohs(ethernet->h_proto);
	ss >> result;

	//ARP related code
	char *temp2 = (char*)calloc(12 , sizeof(char));
	char *arp_mod = (char*)calloc(16 , sizeof(char));
	if(result.compare(ETH_P_ARP_)==0)
	{

		arp_hware_add= modify_eth(arp->__ar_sha); //to get the MAC of ARP
		for(i=0;i<4;i++) //for getting the IP of ARP
		{
			sprintf(temp2,"%d",arp->__ar_sip[i]);
			strcat(arp_mod,temp2);
			if(i != 3)
				strcat(arp_mod,".");
		}
		string s("");

		s = s+arp_hware_add+" / "+arp_mod;

		wtap.add_to_map((char*)s.c_str(),arp_mac);

		result = "ARP";
	}
	else if(result.compare(ETH_P_IP_)==0) //IP related code
	{
		iphdrlen = ((int)ip->ip_hl)*4;
		if(iphdrlen < 20){
                	cout<<"Invalid ip header length "<<iphdrlen<<endl;
                	exit(1);
	        }
		wtap.ttl_to_map((unsigned int)ip->ip_ttl,time_to_live);

		wtap.add_to_map(inet_ntoa(ip->ip_src),ip_source);
		wtap.add_to_map(inet_ntoa(ip->ip_dst),ip_dest);

		wtap.tlayer_to_map((int)ip->ip_p,tl_protocols);
		
		if((int)ip->ip_p == 6)
		{
			struct tcphdr *tcpf = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct ip));
			wtap.ttl_to_map(ntohs(tcpf->source),tcp_src_port);	
			wtap.ttl_to_map(ntohs(tcpf->dest),tcp_dest_port);

			if((((int)tcpf->doff)*4) < 20)
			{
					cout<<"This is an invalid TCP header"<<endl;
					exit(1);
			}
			if(ntohs(tcpf->urg))
				curg++;
			if(ntohs(tcpf->ack))
                                cack++;
			if(ntohs(tcpf->psh))
                                cpsh++;
			if(ntohs(tcpf->rst))
                                crst++;
			if(ntohs(tcpf->syn))
                                csyn++;
			if(ntohs(tcpf->fin))
                                cfin++;
								
			//TCP Flags
			if((((int)tcpf->doff)*4) > 20)
			{
			//t_option* topt = (t_option*)(packet +sizeof(struct ethhdr) + iphdrlen + 20);//(((int)tcph->doff)*4) );
			uint8_t * temp = (uint8_t *)(packet +sizeof(struct ethhdr) + iphdrlen + 20);//(((int)tcph->doff)*4) );


			int opt_len = (((int)tcpf->doff)*4)-20;
			//cout<<"opt length : "<<opt_len<<" "  ;
			int counter = 0;
			bool flag1 = true;
			while( counter != opt_len )
			{
				t_option* topt = (t_option*)temp;

				//if(flag1 == true )
				//wtap.ttl_to_map((int)topt->type,options);
				if(((int) topt->type) == 0 )
					break;	
				if(((int) topt->type) == 1 )//|| ((int) topt->type) == 0)
			  	{ 

					++counter ;
			     		++temp;

			     		if(flag1 == true )
			     			wtap.ttl_to_map((int)topt->type,options);

			     	flag1=false;
			     	continue;
			  	}
				wtap.ttl_to_map((int)topt->type,options);

			 	temp += (int)topt->size;
			 	counter+=(int)topt->size;
			}

			}
		}
		else if((int)ip->ip_p == 17)
		{
			struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + iphdrlen);
			wtap.ttl_to_map(ntohs(udp->source),udp_src_port);
                        wtap.ttl_to_map(ntohs(udp->dest),udp_dest_port);
		}
		else if((int)ip->ip_p == 1)
		{
			struct icmphdr *icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + iphdrlen);
                        wtap.ttl_to_map((unsigned int)icmp->type,icmp_types);
                        wtap.ttl_to_map((unsigned int)icmp->code,icmp_codes);
		}
		result = "IP";
	}

	wtap.add_to_map((char*)result.c_str(), n_protocols);

}

void Wiretap :: open_file()
{

char errbuf[65535];

	pcap_handle = pcap_open_offline(fname,errbuf);
	if(pcap_handle==NULL)
	{
		cout<<"Error with the capture! "<<errbuf<<endl;
		exit(1);
	}
	
	if(pcap_datalink(pcap_handle) != DLT_EN10MB)
	{
		cout<<"capture is not of type ethernet:\nExiting.. "<<pcap_datalink(pcap_handle)<<endl;
		exit(1);
	}

}


//this is not a member function of the class Wiretap
void callback(unsigned char *args1, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	
	wtap.packet_count++;
	wtap.total_pkt_size = wtap.total_pkt_size + header->len;
	wtap.end_time = header->ts.tv_sec;
	if(wtap.packet_count==1)
	{
		wtap.start_time = wtap.end_time;
		wtap.min_size = header->len;
	}
	if(header->len < wtap.min_size)
		wtap.min_size = header->len;
	if(header->len > wtap.max_size)
		wtap.max_size = header->len;
	wtap.ethernet_addr(packet);
}

void Wiretap :: print_summary()
{
	//printing the start time
	char s_time[100];
	strftime((char*)s_time,sizeof(s_time),"%Y-%m-%d   %T ",localtime(&wtap.start_time));
	cout<<endl<<endl<<"---------------SUMMARY--------------------"<<endl;
	cout<<"Capture start date	: "<<s_time<<endl;

	//printing the duration
	cout<<"Capture duration	: "<< wtap.end_time - wtap.start_time<<" seconds"<<endl;

	cout<<"Packets in capture	: "<<wtap.packet_count<<endl;

	cout<<"Minimum packet size	: "<<wtap.min_size<<endl;
	cout<<"Maximum packet size	: "<<wtap.max_size<<endl;
	cout<<"Average packet size	: "<<(float)wtap.total_pkt_size / wtap.packet_count<<endl;
    	cout<<"------------------------------------------"<<endl;

}

void print_map(map<string, int> &t_map)
{
	std::map<string,int>::iterator it = t_map.begin();
	if(t_map.size())
	{
	for (it=t_map.begin(); it!=t_map.end(); ++it)
		    std::cout << it->first << " :  " << it->second << '\n';
	}
	else
		cout<<"(no results)"<<endl;
}

void print_map_ttl(map<unsigned int, int> &t_map)
{

	std::map<unsigned int,int>::iterator it = t_map.begin();
	if(t_map.size())
	{
	for (it=t_map.begin(); it!=t_map.end(); ++it)
		    std::cout << it->first << " : " << it->second << '\n';
	}
	else
		cout<<"(no results)"<<endl;
}

void print_flags(){
	cout<<"URG: "<<curg<<endl;
        cout<<"ACK: "<<cack<<endl;
        cout<<"PSH: "<<cpsh<<endl;
        cout<<"RST: "<<crst<<endl;
        cout<<"SYN: "<<csyn<<endl;
        cout<<"FIN: "<<cfin<<endl;
	cout<<endl;
}

void print_help(){
	 cout<<endl<<"====================================================="<<endl;
         cout<<"The project takes a pcap file as an input"<<'\n'<<
                 "from the user. The file has several packets"<<'\n'<<
                 "which are first described to be of type ether"<<'\n'<<
                 "or not. After that the various header info of"<<'\n'<<
                 "the packets are printed. The info includes:-"<<'\n'<<
                 "1.  MAC Source Address"<<'\n'<<
                 "2.  MAC Destination Address"<<'\n'<<
                 "3.  IP Source Address"<<'\n'<<
                 "4.  IP Destination Address"<<'\n'<<
                 "5.  Time to Live"<<'\n'<<
                 "6.  Different Protocols (IP,ARP,Others)"<<'\n'<<
                 "7.  States whether TCP,IP,UDP,ICMP"<<'\n'<<
                 "8.  Unique ARP Participants"<<'\n'<<
                 "9.  TCP and UDP Source and Destination Port Numbers"<<'\n'<<
                 "10. ICMP Types and Codes."<<'\n'<<
                 "======================================================"<<endl<<endl;
}

void check_arguments(int argc, char* argv[]){
	
	int x = 1;
        if(argc == 5 || argc == 1)
        {
                cout<<"Invalid option. Please check"<<endl;
                exit(1);
        }
	if(argc == 2 && (!(strcmp(argv[x] , "--help") == 0)))
	{
		cout<<"Please enter the missing credentials."<<endl;
		exit(1);
	}
        if((argc == 3) && (((strcmp(argv[x] , "--open") == 0) && (strcmp(argv[x+1] , "--help") == 0))
                        || ((strcmp(argv[x+1] , "--open") == 0) && (strcmp(argv[x] , "--help") == 0))))
        {
                cout<<"Please enter valid options"<<endl;
                exit(1);
        }

        for(x = 1 ; x < argc ; x++)
        {
                if(argc == 4){
                        if((strcmp(argv[x] , "--open") == 0) && (strcmp(argv[x+2] , "--help") == 0))
                        {
                                string s;
                                int pos;
                                s = argv[x+1];
                                if(s.find(".pcap") == -1)
                                {
                                        cout<<"Please enter a valid .pcap file"<<endl;
                                        exit(1);
                                }
                                print_help();
                                fname = argv[x+1];
                        }
                        else if((strcmp(argv[x] , "--help") == 0) && (strcmp(argv[x+1] , "--open") == 0))
                        {
                                string s;
                                int pos;
                                s = argv[x+2];
                                if(s.find(".pcap") == -1)
                                {
                                        cout<<"Please enter a valid .pcap file"<<endl;
                                        exit(1);
                                }

                                print_help();
                                fname = argv[x+2];
                         }
                break;
                }
                if(strcmp(argv[x] , "--open") == 0)
                {
                        string s;
                        int pos;
                        s = argv[x+1];
                        if(s.find(".pcap") == -1)
                        {
                                cout<<"Please enter a valid .pcap file"<<endl;
                                exit(1);
                        }
                        fname = argv[x+1];
                        break;
                }
                else if(strcmp(argv[x] , "--help") == 0)
                {
                        if(argv[x+1]){
                                cout<<"Please enter a valid option"<<endl;
                                exit(1);
                        }
                        cout<<endl;
                        print_help();
                        exit(1);
                }
        }

}
int main(int argc, char* argv[])
{
	check_arguments(argc,argv);
		         	
	wtap.open_file();
	unsigned char *args;

	pcap_loop(wtap.pcap_handle, -1, callback, args);

	wtap.print_summary();

	cout<<"\n\n=========== Link Layer ========="<<endl;

	cout<<"\n\n------ Ethernet Source ------ "<<endl<<endl;
	print_map(wtap.eth_src);

	cout<<"\n\n------ Ethernet Destination ------"<<endl<<endl;
	print_map(wtap.eth_dest);

	cout<<"\n\n======== Network Layer ========"<<endl<<endl;

	cout<<"\n\n ------Network Layer Protocols------ "<<endl<<endl;
	print_map(wtap.n_protocols);

	cout<<"\n\n------ IP Source ------"<<endl<<endl;
	print_map(wtap.ip_source);

	cout<<"\n\n------ IP Destination ------"<<endl<<endl;
	print_map(wtap.ip_dest);

	cout<<"\n\n------ Time to Live ------"<<endl<<endl;
	print_map_ttl(wtap.time_to_live);

	cout<<"\n\n------ Unique ARP participants ------"<<endl<<endl;
	print_map(wtap.arp_mac);

	cout<<"\n\n========= Transport Layer =========="<<endl<<endl;

	cout<<"\n\n------ Transport Layer protocols------ "<<endl<<endl;
	print_map(wtap.tl_protocols);

	cout<<"\n\n========= Transport Layer: TCP =========="<<endl<<endl;
	cout<<"\n\n--------- Source TCP Ports ---------"<<endl<<endl;
	print_map_ttl(wtap.tcp_src_port);

	cout<<"\n\n--------- Destination TCP Ports ---------"<<endl<<endl;
        print_map_ttl(wtap.tcp_dest_port);
	
	cout<<"\n\n--------- TCP FLAGS --------"<<endl<<endl;
	print_flags();
	
	cout<<"\n\n--------- TCP OPTIONS ---------"<<endl<<endl;
	print_map_ttl(wtap.options);

	cout<<"\n\n========= Transport Layer: UDP =========="<<endl<<endl;
	cout<<"\n\n--------- Source UDP Ports ---------"<<endl<<endl;
        print_map_ttl(wtap.udp_src_port);

        cout<<"\n\n---------Destination UDP Ports---------"<<endl<<endl;
        print_map_ttl(wtap.udp_dest_port);

	cout<<"\n\n========= Transport Layer: ICMP =========="<<endl<<endl;
        cout<<"\n\n--------- ICMP TYPES ---------"<<endl<<endl;
        print_map_ttl(wtap.icmp_types);

        cout<<"\n\n--------- ICMP CODES ---------"<<endl<<endl;
        print_map_ttl(wtap.icmp_codes);
	cout<<endl;
	
	cout<<"~~~~~~~~~~~~~~~~~ END OF PROGRAM ~~~~~~~~~~~~~~~~~~~~~~~"<<endl<<endl;

	pcap_close(wtap.pcap_handle);

return 0;
}

