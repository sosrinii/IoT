// DHCP Library
// Jason Losh

//-----------------------------------------------------------------------------
// Hardware Target
//-----------------------------------------------------------------------------

// Target Platform: -
// Target uC:       -
// System Clock:    -

// Hardware configuration:
// -

//-----------------------------------------------------------------------------
// Device includes, defines, and assembler directives
//-----------------------------------------------------------------------------

#include <stdio.h>
#include "dhcp.h"
#include "timer.h"
#include "eth0.h"

#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

#define DHCP_DISABLED   0
#define DHCP_INIT       1
#define DHCP_SELECTING  2
#define DHCP_REQUESTING 3
#define DHCP_TESTING_IP 4
#define DHCP_BOUND      5
#define DHCP_RENEWING   6
#define DHCP_REBINDING  7
#define DHCP_INITREBOOT 8 // not used since ip not stored over reboot
#define DHCP_REBOOTING  9 // not used since ip not stored over reboot

// ------------------------------------------------------------------------------
//  Globals
// ------------------------------------------------------------------------------

uint8_t dhcpState = DHCP_DISABLED;
uint32_t XID = 0x23615737;
uint8_t offerIpAddress[IP_ADD_LENGTH] = {0,0,0,0};
uint8_t offerIpGWAddress[IP_ADD_LENGTH] = {0,0,0,0};
uint32_t ipLeaseTime;
uint32_t t1;
uint32_t t2;
uint32_t RenewalTime;
uint32_t RebindingTime;
bool requestBit;

// ------------------------------------------------------------------------------
//  Structures
// ------------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Subroutines
//-----------------------------------------------------------------------------

// State functions

void dhcpSetState(uint8_t state)
{
    dhcpState = state;
}

uint8_t dhcpGetState()
{
    return dhcpState;
}
void cbDiscover()
{
    dhcpState = DHCP_INIT;
}
void cbRequest()
{
    dhcpState = DHCPREQUEST;
}
void cbARPresponse()
{
    dhcpState = DHCP_BOUND;

}
void cbRenewRequest()
{
    dhcpState = DHCPREQUEST;
}
void cbRenewPeriodic()
{
    dhcpState = DHCPREQUEST;
}
void cbRebind()
{
    dhcpState = DHCP_REBINDING;
}
void cbLeaseTimer()
{
    dhcpState = DHCPRELEASE;
}
void cbtimer1()
{
    requestBit = 1;
    dhcpState = DHCP_RENEWING;
    startPeriodicTimer((_callback)cbRenewPeriodic, 15);

}
void cbtimer2()
{
    requestBit = 1;
    dhcpState = DHCP_REBINDING;
    startPeriodicTimer((_callback)cbRebind, 15);
}

// Send DHCP message
void dhcpSendMessage(etherHeader *ether, uint8_t type)
{
    uint32_t sum;
    uint8_t i, opt;
    uint16_t tmp16;
    uint8_t mac[6];

    // Ether frame
    etherGetMacAddress(mac);
    for (i = 0; i < HW_ADD_LENGTH; i++)
    {
        ether->destAddress[i] = 0xFF;
        ether->sourceAddress[i] = mac[i];
    }
    ether->frameType = htons(0x800);

    // IP header
    ipHeader *ip = (ipHeader*) ether->data;
    ip->revSize = 0x45;
    ip->typeOfService = 0;
    ip->id = 0;
    ip->flagsAndOffset = 0;
    ip->ttl = 128;
    ip->protocol = 17;
    ip->headerChecksum = 0;

    if(dhcpState == DHCP_RENEWING || dhcpState == DHCPRELEASE)
    {
        uint8_t *tempIP, *tempServerAdd;
        etherGetIpAddress(tempIP);
        etherGetIpDnsAddress(tempServerAdd);
        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            ip->destIp[i] = tempServerAdd[i];
            ip->sourceIp[i] = tempIP[i];
        }
    }
    else if(dhcpState == DHCP_REBINDING)
    {
        uint8_t *tempIP;
        etherGetIpAddress(tempIP);
        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            ip->destIp[i] = 0xFF;
            ip->sourceIp[i] = tempIP[i];
        }
    }
    else
    {
        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            ip->destIp[i] = 0xFF;
            ip->sourceIp[i] = 0x0;
        }
    }


    // UDP header
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    udp->sourcePort = htons(68);
    udp->destPort = htons(67);

    // DHCP
    dhcpFrame *dhcp = (dhcpFrame*) udp->data;
    dhcp->op = 1;
    // continue dhcp message here
    dhcp->htype = 0x01;
    dhcp->hlen = 6;
    dhcp->hops = 0;
    dhcp->xid = XID;
    dhcp->secs = 0;
    dhcp->flags = htons(0x8000);
    if(dhcpState == DHCP_RENEWING || dhcpState == DHCPRELEASE)
    {
        uint8_t *tempIP;
        etherGetIpAddress(tempIP);
        for (i = 0; i < 4; i++)
        {
            dhcp->ciaddr[i] = tempIP[i];
        }

    }
    for (i = 0; i < 4; i++)
    {
        dhcp->ciaddr[i] = 0;
    }
    for (i = 0; i < 4; i++)
    {
        dhcp->yiaddr[i] = 0;
    }
    for (i = 0; i < 4; i++)
    {
        dhcp->siaddr[i] = 0;
    }
    for (i = 0; i < 4; i++)
    {
        dhcp->giaddr[i] = 0;
    }
    for (i = 0; i < 6; i++)
    {
        dhcp->chaddr[i] = mac[i];
    }
    for (i = 6; i < 16; i++)
    {
        dhcp->chaddr[i] = 0;
    }
    for (i = 0; i < 192; i++)
    {
        dhcp->data[i] = 0;
    }
    // add magic cookie
    dhcp->magicCookie = 0x63538263;

    uint8_t *data = (uint8_t*) &dhcp->options;
    // send dhcp message type (53)
    uint8_t index = 0;
    data[index++] = 53;
    data[index++] = 1;
    data[index++] = type;

    // client identifier
    data[index++] = 61;
    data[index++] = 7;
    data[index++] = 1;
    data[index++] = mac[0];
    data[index++] = mac[1];
    data[index++] = mac[2];
    data[index++] = mac[3];
    data[index++] = mac[4];
    data[index++] = mac[5];
    // send parameter request list (55)
    data[index++] = 55;
    data[index++] = 8;
    data[index++] = 1;
    data[index++] = 2;
    data[index++] = 3;
    data[index++] = 4;
    data[index++] = 6;
    data[index++] = 54;
    data[index++] = 58;
    data[index++] = 59;
    // end
    if(type == DHCPDISCOVER)
    {
        data[index++] = 255;
    }
    else if(type == DHCPREQUEST)
    {
        // send requested ip (50) as needed
        uint8_t k = 0, i = 0;
        data[index++] = 50;
        data[index++] = 4;

        for(i = 0; i< IP_ADD_LENGTH; i++)
        {
            data[index++] = offerIpAddress[k++];
        }
        // send server ip (54) as needed
        k = 0, i = 0;
        data[index++] = 54;
        data[index++] = 4;
        for(i = 0; i<IP_ADD_LENGTH; i++)
        {
            data[index++] = offerIpGWAddress[k++];
        }
        data[index++] = 255;
    }
    if(type == DHCPRELEASE)
    {
        data[index++] = 255;
    }

    // calculate dhcp size, update ip and udp lengths
    int dhcpSize = 240 + index;
    ip->length = htons(((ip->revSize & 0xF) * 4) + 8 + dhcpSize);



    // calculate ip header checksum, calculate udp checksum
    sum = 0;
    etherSumWords(&ip->revSize, 10, &sum);
    etherSumWords(ip->sourceIp, ((ip->revSize & 0xF) * 4) - 12, &sum);
    ip->headerChecksum = getEtherChecksum(sum);

   // etherCalcIpChecksum(ip);


    // 32-bit sum over pseudo-header
    sum = 0;
    udp->length = htons(8 + dhcpSize);
    etherSumWords(ip->sourceIp, 8, &sum);
    tmp16 = ip->protocol;
    sum += (tmp16 & 0xff) << 8;
    etherSumWords(&udp->length, 2, &sum);
    // add udp header
    udp->check = 0;
    etherSumWords(udp, 8 + dhcpSize, &sum);
    udp->check = getEtherChecksum(sum);

    // send packet with size = ether hdr + ip header + udp hdr + dhcp_size
    etherPutPacket(ether, 14 + ((ip->revSize & 0xF) * 4) + 8 + dhcpSize);
    // send packet
}

uint8_t* getOption(etherHeader *ether, uint8_t option, uint8_t* length)
{
//    ipHeader *ip = (ipHeader*) ether->data;
//    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
//    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;

    int j=0;
    uint8_t len = *length;
    length++;
    uint8_t *temp;


    for(j = 0; j<len; j++)
    {
        temp[j] = *length;
        length++;
    }
    // suggest this function to programatically extract the field value
    return temp;
}

// Determines whether packet is DHCP offer response to DHCP discover
// Must be a UDP packet
bool dhcpIsOffer(etherHeader *ether, uint8_t ipOfferedAdd[])
{
    ipHeader *ip = (ipHeader*) ether->data;
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;
    bool ok;

    // return true if destport=68 and sourceport=67, op=2, xid correct, and offer msg

    uint8_t *data = (uint8_t*) &dhcp->options;

    if(udp->destPort == htons(68) && udp->sourcePort == htons(67) && dhcp->op == 2 && dhcp->xid == XID  && data[2] == DHCPOFFER)
    {
        ok = true;
    }
    else
        ok = false;
    return ok;
}

// Determines whether packet is DHCP ACK response to DHCP request
// Must be a UDP packet
bool dhcpIsAck(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*) ether->data;
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;
    // return true if destport=68 and sourceport=67, op=2, xid correct, and ack msg
    bool ok;
    uint8_t *data = (uint8_t*) &dhcp->options;
    if(udp->destPort == htons(68) && udp->sourcePort == htons(67) && dhcp->op == 2 && dhcp->xid == XID  && data[2] == DHCPACK)
    {
        ok = true;
    }
    else
        ok = false;
    return ok;
}

// Handle a DHCP ACK
void dhcpHandleAck(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*) ether->data;
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;

    uint8_t *data = (uint8_t*) &dhcp->options;
    uint8_t i=3;
//    uint8_t *len, *tempData;
//    uint8_t j = 0, length, temp;

    // extract offered IP address
    etherSetIpAddress(dhcp->yiaddr);

    // store sn, gw, dns, and time from options
    // store dns server address for later use

//    uint8_t j, len, *length, *tempData;
//    uint8_t temp;
//    i = 3; // skipping type 53 in options
//    while( dhcp->options[i]!= 255)
//    {
//        switch(dhcp->options[i])
//        {
//        case 1: // save SN mask
//            length = &dhcp->options[i+1];
//            len = dhcp->options[++i];
//            i++;
////            for (j = 0; j < len; j++)
////            {
//                tempData = getOption(ether, dhcp->options[i], length);
//                etherSetIpSubnetMask(tempData);
//                i++;
////            }
//            break;
//        case 3: // save router IP
//            length = &dhcp->options[i+1];
//            len = dhcp->options[++i];
//            i++;
////            for (j = 0; j < len; j++)
////            {
//                tempData = getOption(ether, dhcp->options[i], length);
//                etherSetIpGatewayAddress(tempData);
//                i++;
////            }
//            break;
//        case 51:// save IP address lease time
//            length = &dhcp->options[i+1];
//            len = dhcp->options[++i];
//            ipLeaseTime = 0;
//            j=0;
////            while(j < (len-1))
////            {
//                temp = dhcp->options[++i];
//                ipLeaseTime += (temp & 0xff) ;
//                ipLeaseTime = ipLeaseTime << 8;
//                j++;
////            }
//            temp = dhcp->options[++i];
//            ipLeaseTime += temp;
//            i++;
//            break;
//        case 54:// store DHCP server Identifier in buffer
//            length = &dhcp->options[i+1];
//            len = dhcp->options[++i];
//            i++;
//            tempData = getOption(ether, dhcp->options[i], length);
//            etherSetIpDnsAddress(tempData);
//            i++;
//            break;
//        default:
////            len = dhcp->options[++i];
////            i = i + len;
//            i++;
//        }
//    }

//        uint8_t j, *len, length, *tempData;
//        uint8_t temp;
//        i = 3, j = 0; // skipping type 53 in options
//
//        while(data[i]!=255)
//        {
//            switch(dhcp->options[i])
//            {
//            case 1:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//                    //  tempData = getOption(ether, dhcp->options[i], len);
//                    etherSetIpSubnetMask(tempData);
//                }
//                i++;
//                break;
//            case 3:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//                    etherSetIpGatewayAddress(tempData);
//                }
//                i++;
//                break;
//            case 6:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//
//                    etherSetIpDnsAddress(tempData);
//                }
//                i++;
//                break;
//            case 54:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//                    etherSetIpDnsAddress(tempData);
//                }
//                i++;
//                break;
//            case 51:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    ipLeaseTime = 0;
//                    length = *len;
//                    while(j < (length-1))
//                    {
//
//                        temp = dhcp->options[++i];
//                        length = *len;
//                        ipLeaseTime = (temp&0xff);
//                        ipLeaseTime = ipLeaseTime << 8;
//                        j++;
//                    }
//                    temp = dhcp->options[++i];
//                    ipLeaseTime += temp;
//                }
//                i++;
//                break;
//            case 58:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//                    RenewalTime = ntohl(*tempData);
//                }
//                i++;
//                break;
//            case 59:
//                len = &dhcp->options[++i];
//                length = *len;
//                if(length == 4)
//                {
//                    for(j = 0; j<length; j++)
//                    {
//                        tempData[j] = dhcp->options[i++];
//                    }
//                    RebindingTime = ntohl(*tempData);
//                }
//                i++;
//                break;
//        default:
////            len = &dhcp->options[++i];
////            length = *len;
////            i = i+length;
//            i++;
//        }
//    }

    //original
            uint8_t j, *len, length, *tempData;
            uint8_t temp;
            i = 0;
    while(dhcp->options[i]!=255)
       {
           switch(dhcp->options[i])
           {
           case 1:
               len = &dhcp->options[++i];
               i++;
               length = *len;
               if(length == 4)
               {
                   tempData = getOption(ether, dhcp->options[i], len);
                   i = i+length;
                   etherSetIpSubnetMask(tempData);
               }
               else
                   i++;
               break;
           case 3:
               len = &dhcp->options[++i];
               length = *len;
               i++;
               if(length == 4)
               {
                   tempData = getOption(ether, dhcp->options[i], len);
                   i = i+length;
                   etherSetIpGatewayAddress(tempData);
               }
               else
                   i++;
               break;
           case 6:
               len = &dhcp->options[++i];
               i++;
               length = *len;
               if(length == 4)
               {
                   tempData = getOption(ether, dhcp->options[i], len);
                   i = i+length;
                   etherSetIpDnsAddress(tempData);
               }
               else
                   i++;
               break;
           case 54:
               len = &dhcp->options[++i];

               length = *len;
               if(length == 4)
               {
                   tempData = getOption(ether, dhcp->options[i], len);
                   i = i+length;
                   etherSetIpDnsAddress(tempData);
               }
               else
                   i++;
               break;
           case 51:
               len = &dhcp->options[++i];
               ipLeaseTime = 0;
               length = *len;
               while(j < (length-1))
               {

               temp = dhcp->options[++i];
               ipLeaseTime = (temp&0xff);
               ipLeaseTime = ipLeaseTime << 8;
               j++;
               }
               temp = dhcp->options[++i];
               ipLeaseTime += temp;
               i++;
               break;
           case 58:
               len = &dhcp->options[++i];
               length = *len;
               if(length == 4)
               {
                   tempData = getOption(ether, dhcp->options[i], len);
                   RenewalTime = ntohl(*tempData);
                   i = i +length;
               }
               else
                   i++;
               break;
           case 59:
               len = &dhcp->options[++i];
               length = *len;
               if(length == 4)
               {

                   tempData = getOption(ether, dhcp->options[i], len);
                   RebindingTime = ntohl(*tempData);
                   i = i+length;
               }
               i++;
               break;
           default:
               i++;
           }
       }

    // store lease, t1, and t2
    t1 = ipLeaseTime>>1;
    t2 = (ipLeaseTime>>7)&6;

    // stop new address needed timer, t1 timer, t2 timer
    stopTimer((_callback)cbDiscover);

    // start t1, t2, and lease end timers
    startOneshotTimer((_callback)cbtimer1, t1);
    startOneshotTimer((_callback)cbtimer2, t2);
    startOneshotTimer((_callback)cbLeaseTimer, ipLeaseTime);
}

void dhcpSendPendingMessages(etherHeader *ether)
{
    // if discover needed, send discover, enter selecting state
    if (dhcpState == DHCP_INIT)
    {
        dhcpSendMessage(ether, DHCPDISCOVER);
        startPeriodicTimer((_callback)cbDiscover, 15); // start timer
        dhcpState = DHCP_SELECTING;
    }
    else if (dhcpState == DHCP_REQUESTING) // if request needed, send request
    {
        if(requestBit == 1)
        {
            dhcpSendMessage(ether, DHCPREQUEST);
            //startPeriodicTimer((_callback)cbDiscover, 15);
            dhcpState = DHCP_REQUESTING;
            requestBit = 0;
        }
    }
    else if (dhcpState == DHCP_RENEWING)     // if renew needed, send release
    {
        if(requestBit == 1)
        {
            dhcpSendMessage(ether, DHCP_RENEWING);
            startPeriodicTimer((_callback)cbRenewRequest, 15);
            requestBit = 0;
        }

    }
    else if (dhcpState == DHCP_REBINDING)     // if rebind needed, send release
    {
        if(requestBit == 1)
        {
            dhcpSendMessage(ether, DHCP_REBINDING);
        }
    }
    else if (dhcpState == DHCPRELEASE)     // if release needed, send release
    {
        dhcpSendMessage(ether, DHCPRELEASE);
        uint8_t erase[IP_ADD_LENGTH] = {0,0,0,0};
        etherSetIpAddress(erase);
        etherSetIpDnsAddress(erase);
        etherSetIpGatewayAddress(erase);
        etherSetIpSubnetMask(erase);
        etherSetIpTimeServerAddress(erase);
    }
    else if (dhcpState == DHCP_DISABLED)     // if release needed, send release
    {
        if(requestBit == 1)
        {
            dhcpSendMessage(ether, DHCPRELEASE);
            uint8_t erase[IP_ADD_LENGTH] = {0,0,0,0};
            etherSetIpAddress(erase);
            etherSetIpDnsAddress(erase);
            etherSetIpGatewayAddress(erase);
            etherSetIpSubnetMask(erase);
            etherSetIpTimeServerAddress(erase);
            stopTimer((_callback)cbDiscover);
            stopTimer((_callback)cbRequest);
            stopTimer((_callback)cbARPresponse);
            stopTimer((_callback)cbRenewRequest);
            stopTimer((_callback)cbRebind);
            stopTimer((_callback)cbLeaseTimer);
            requestBit = 0;
        }
    }
}

void dhcpProcessDhcpResponse(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*) ether->data;
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;

    int i;
    for(i = 0; i<4; i++)
    {
        offerIpAddress[i] = dhcp->yiaddr[i];
    }
    for(i = 0; i<4; i++)
    {
        offerIpGWAddress[i] = ip->sourceIp[i];
    }
    if(dhcpIsOffer(ether,&offerIpAddress[0]))
    {
        dhcpSendMessage(ether, DHCPREQUEST);
        dhcpState = DHCPREQUEST;
        stopTimer((_callback)cbDiscover);
        startPeriodicTimer((_callback)cbRequest, 15);
    }
    if(dhcpIsAck(ether))
    {
        uint8_t ipFrom[IP_ADD_LENGTH], ipTo[IP_ADD_LENGTH];
        for (i = 0; i < IP_ADD_LENGTH; i++)
        {
            ipFrom[i] = offerIpAddress[i];
            ipTo[i] = offerIpAddress[i];
           // offerIpAddress[i] = dhcp->yiaddr[i];
        }
        etherSendArpRequest(ether,&ipFrom[0], &ipTo[0]);
        dhcpState = DHCP_TESTING_IP;
        startOneshotTimer((_callback)cbARPresponse, 1);
        dhcpHandleAck(ether);
        dhcpState = DHCP_BOUND;
    }
    // if offer, send request and enter requesting state
    // if ack, call handle ack, send arp request, enter ip conflict test state
}

void dhcpProcessArpResponse(etherHeader *ether)
{
    ipHeader *ip = (ipHeader*) ether->data;
    udpHeader *udp = (udpHeader*) ((uint8_t*) ip + ((ip->revSize & 0xF) * 4));
    dhcpFrame *dhcp = (dhcpFrame*) &udp->data;
    // if in conflict resolution, if a response matches the offered add,
    //  send decline and request new address
    uint8_t i = 0;
    bool flag;

    if(dhcpState == DHCP_TESTING_IP)
    {
        for(i = 0; i<IP_ADD_LENGTH; i++)
        {
            if(dhcp->yiaddr[i] == offerIpAddress[i])
            {
                flag = true;
            }
            else
                flag = false;
        }
        if(flag)
        {
            dhcpSendMessage(ether, DHCPDECLINE);
            dhcpState = DHCP_INIT;
        }
    }
    stopTimer((_callback)cbARPresponse);
}

// DHCP control functions

void dhcpEnable()
{
    dhcpState = DHCP_INIT;
    // request new address
}

void dhcpDisable()
{
    dhcpState = DHCP_DISABLED;
    // set state to disabled, stop all timers
}

bool dhcpIsEnabled()
{
    return (dhcpState != DHCP_DISABLED);
}

void dhcpRequestRenew()
{
    dhcpState = DHCP_RENEWING;
}

void dhcpRequestRebind()
{
    dhcpState = DHCP_REBINDING;
}

void dhcpRequestRelease()
{
    dhcpState = DHCPRELEASE;
}
uint32_t dhcpGetLeaseSeconds()
{
    return 0;
}
