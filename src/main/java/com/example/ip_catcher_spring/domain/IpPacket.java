package com.example.ip_catcher_spring.domain;

import jpcap.packet.*;

import java.net.InetAddress;
import java.util.List;

public class IpPacket {
    public static enum PACKET_TYPE{
        TCP, UDP, ICMP, OTHERS
    }

    private int packetType;
    //数据链路层
    private String ethernetFrame = "以太帧首部: jpcap.packet.EthernetPacket";
    private String macSource = "源mac地址: ";
    private String maxDestination = "目的mac地址: ";
    private String frameType = "帧类型: ";
    //ip数据包参数
    private String ipHeader = "IP报文首部: ";
    private String version = "版本version: ";
    private String secStamp = "时间戳(秒): ";
    private String usecStamp = "时间戳(毫秒): ";
    private String ipSource = "源IP: ";
    private String ipDestination = "目的IP: ";
    private String protocol = "协议protocol: ";
    private String priority = "优先权priority: ";
    private String hop = "生存时间hop: ";
    private String RF = "标志位RF:保留位必须为false: ";
    private String DF = "标志位DF: ";
    private String MF = "标志位MF: ";
    private String offset = "片偏移offset: ";
    private String identity = "标识参数: ";
    //tcp
    private String tcpHeader = "TCP报文首部: ";
    private String tcpDF = "标志位DF: ";
    private String tcpMF = "标志位MF: ";
    private String tcpOffset = "片偏移offset: ";
    private String tcpIdentity = "TCP标识ident: ";
    private String tcpSourcePort = "源端口: ";
    private String tcpDestinationPort = "目的端口: ";
    private String sequence = "seq序号: ";
    private String window = "窗口大小: ";
    private String ackFlag = "ACK标志: ";
    private String ack = "ack: ";
    private String tcpLength = "TCP报文长度length: " ;
    //udp
    private String udpHeader = "UDP报文首部: ";
    private String udpDF = "标志位DF: ";
    private String udpMF = "标志位MF: ";
    private String udpOffset = "片偏移offset: ";
    private String udpIdentity = "标识参数: ";
    private String udpSourcePort =  "源端口: ";
    private String udpDestinationPort = "目的端口: ";
    private String udpLength = "UDP报文长度: ";
    //ICMP
    private String icmpHeader = "ICMP报文首部: ";
    private String icmpDF = "标志位DF: ";
    private String icmpMF = "标志位MF: ";
    private String icmpOffset = "片偏移offset: ";
    private String icmpIdentity = "标识参数: ";
    private String icmpType = "ICMP报文类型: ";
    private String icmpCode = "ICMP报文代码code: ";
    //arp
    private String hardWare = "硬件类型hardtop: ";
    private String arpPrototype = "协议类型prototype: ";
    private String arpOperation = "操作字段operation: ";
    private String arpHeader = "IP首部: ";
    private String arpSender = "发送方硬件地址: ";
    private String arpTarget = "接收方硬件地址: ";
    private String arpSenderIp = "发送方IP地址: ";
    private String arpTargetIp = "接收方IP地址: ";

    public void commonSetter(Packet packet){
        EthernetPacket dataLinkPacket = (EthernetPacket) packet.datalink;
        macSource+= dataLinkPacket.getSourceAddress();
        maxDestination+= dataLinkPacket.getDestinationAddress();
        frameType+=Short.toString(dataLinkPacket.frametype);
    }

    public void IpSetter(Packet packet){
        IPPacket ipPacket = (IPPacket) packet;
        ipHeader+=ipPacket.version == 4 ?ipPacket.src_ip + "->" + ipPacket.dst_ip + " protocol(" + ipPacket.protocol + ") priority(" + ipPacket.priority + ") " + (ipPacket.d_flag ? "D" : "") + (ipPacket.t_flag ? "T" : "") + (ipPacket.r_flag ? "R" : "") + " hop(" + ipPacket.hop_limit + ") " + (ipPacket.rsv_frag ? "RF/" : "") + (ipPacket.dont_frag ? "DF/" : "") + (ipPacket.more_frag ? "MF" : "") + " offset(" + ipPacket.offset + ") ident(" + ipPacket.ident + ")" : ipPacket.src_ip + "->" + ipPacket.dst_ip + " protocol(" + ipPacket.protocol + ") priority(" + ipPacket.priority + ") flowlabel(" + ipPacket.flow_label + ") hop(" + ipPacket.hop_limit + ")";
        version+=Byte.toString(ipPacket.version);
        secStamp+=Long.toString(ipPacket.sec);
        usecStamp+=Long.toString(ipPacket.usec);
        ipSource+= ipPacket.src_ip;
        ipDestination+=ipPacket.dst_ip;
        priority += Byte.toString(ipPacket.priority);
        hop += Short.toString(ipPacket.hop_limit);
        RF+=ipPacket.rsv_frag;
        DF+=ipPacket.dont_frag;
        MF+=ipPacket.more_frag;
        offset+=ipPacket.offset;
        identity+=ipPacket.ident;
    }

    public void tcpSetter(Packet packet){
        TCPPacket tcpPacket = (TCPPacket)packet;
        tcpHeader+=" TCP " + tcpPacket.src_port + " > " + tcpPacket.dst_port + " seq(" + tcpPacket.sequence + ") win(" + tcpPacket.window + ")" + (tcpPacket.ack ? " ack " + tcpPacket.ack_num : "") + " " + (tcpPacket.syn ? " S" : "") + (tcpPacket.fin ? " F" : "") + (tcpPacket.psh ? " P" : "") + (tcpPacket.rst ? " R" : "") + (tcpPacket.urg ? " U" : "");
        tcpDF+=tcpPacket.dont_frag;
        tcpMF+=tcpPacket.more_frag;
        tcpOffset+=tcpPacket.offset;
        tcpIdentity+=tcpPacket.ident;
        tcpSourcePort+=tcpPacket.src_port;
        tcpDestinationPort+=tcpPacket.dst_port;
        sequence+=tcpPacket.sequence;
        window+=tcpPacket.window;
        ackFlag += tcpPacket.ack;
        ack += tcpPacket.ack_num;
        tcpLength+=tcpPacket.length;
    }

    public void udpSetter(Packet packet){
        UDPPacket udpPacket = (UDPPacket) packet;
        udpLength += udpPacket.length;
        udpHeader+=" UDP " + udpPacket.src_port + " > " + udpPacket.dst_port;
        udpDF+=udpPacket.dont_frag;
        udpMF+=udpPacket.more_frag;
        udpOffset+=udpPacket.offset;
        udpIdentity+=udpPacket.ident;
        udpSourcePort+=udpPacket.src_ip;
        udpDestinationPort+=udpPacket.dst_port;
    }

    public void icmpSetter(Packet packet){
        ICMPPacket icmpPacket = (ICMPPacket) packet;
        icmpHeader+="type(" + icmpPacket.type + ") code(" + icmpPacket.code + ")";
        icmpDF+=icmpPacket.dont_frag;
        icmpMF+=icmpPacket.more_frag;
        icmpOffset+=icmpPacket.offset;
        icmpIdentity+=icmpPacket.ident;
        icmpType+=icmpPacket.type;
        icmpCode+=icmpPacket.code;
    }

    public void arpSetter(Packet packet){
        ARPPacket arpPacket = (ARPPacket) packet;
        hardWare+=arpPacket.hardtype;
        arpPrototype+=arpPacket.prototype;
        arpOperation+=arpPacket.operation;
        String buf = "";
        switch(arpPacket.operation) {
            case 1:
                buf+="ARP REQUEST ";
                break;
            case 2:
                buf+="ARP REPLY ";
                break;
            case 3:
                buf+="RARP REQUEST ";
                break;
            case 4:
                buf+="RARP REPLY ";
                break;
            case 5:
            case 6:
            case 7:
            default:
                buf+="UNKNOWN ";
                break;
            case 8:
                buf+="IDENTIFY REQUEST ";
                break;
            case 9:
                buf+="IDENTIFY REPLY ";
        }
        arpHeader+=buf + arpPacket.getSenderHardwareAddress() + "(" + arpPacket.getSenderProtocolAddress() + ") -> " + arpPacket.getTargetHardwareAddress() + "(" + arpPacket.getTargetProtocolAddress() + ")";
        arpSender+=arpPacket.getSenderHardwareAddress();
        arpTarget+=arpPacket.getTargetHardwareAddress();
        arpSenderIp+=arpPacket.getSenderProtocolAddress();
        arpTargetIp+=arpPacket.getTargetProtocolAddress();
    }

    public int getPacketType() {
        return packetType;
    }

    public String getEthernetFrame() {
        return ethernetFrame;
    }

    public String getMacSource() {
        return macSource;
    }

    public String getMaxDestination() {
        return maxDestination;
    }

    public String getFrameType() {
        return frameType;
    }

    public String getIpHeader() {
        return ipHeader;
    }

    public String getVersion() {
        return version;
    }

    public String getSecStamp() {
        return secStamp;
    }

    public String getUsecStamp() {
        return usecStamp;
    }

    public String getIpSource() {
        return ipSource;
    }

    public String getIpDestination() {
        return ipDestination;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getPriority() {
        return priority;
    }

    public String getHop() {
        return hop;
    }

    public String getRF() {
        return RF;
    }

    public String getDF() {
        return DF;
    }

    public String getMF() {
        return MF;
    }

    public String getOffset() {
        return offset;
    }

    public String getIdentity() {
        return identity;
    }

    public String getTcpHeader() {
        return tcpHeader;
    }

    public String getTcpDF() {
        return tcpDF;
    }

    public String getTcpMF() {
        return tcpMF;
    }

    public String getTcpOffset() {
        return tcpOffset;
    }

    public String getTcpIdentity() {
        return tcpIdentity;
    }

    public String getTcpSourcePort() {
        return tcpSourcePort;
    }

    public String getTcpDestinationPort() {
        return tcpDestinationPort;
    }

    public String getSequence() {
        return sequence;
    }

    public String getWindow() {
        return window;
    }

    public String getAckFlag() {
        return ackFlag;
    }

    public String getAck() {
        return ack;
    }

    public String getTcpLength() {
        return tcpLength;
    }

    public String getUdpHeader() {
        return udpHeader;
    }

    public String getUdpDF() {
        return udpDF;
    }

    public String getUdpMF() {
        return udpMF;
    }

    public String getUdpOffset() {
        return udpOffset;
    }

    public String getUdpIdentity() {
        return udpIdentity;
    }

    public String getUdpSourcePort() {
        return udpSourcePort;
    }

    public String getUdpDestinationPort() {
        return udpDestinationPort;
    }

    public String getUdpLength() {
        return udpLength;
    }

    public String getIcmpHeader() {
        return icmpHeader;
    }

    public String getIcmpDF() {
        return icmpDF;
    }

    public String getIcmpMF() {
        return icmpMF;
    }

    public String getIcmpOffset() {
        return icmpOffset;
    }

    public String getIcmpIdentity() {
        return icmpIdentity;
    }

    public String getIcmpType() {
        return icmpType;
    }

    public String getIcmpCode() {
        return icmpCode;
    }

    public String getHardWare() {
        return hardWare;
    }

    public String getArpPrototype() {
        return arpPrototype;
    }

    public String getArpOperation() {
        return arpOperation;
    }

    public String getArpHeader() {
        return arpHeader;
    }

    public String getArpSender() {
        return arpSender;
    }

    public String getArpTarget() {
        return arpTarget;
    }

    public String getArpSenderIp() {
        return arpSenderIp;
    }

    public String getArpTargetIp() {
        return arpTargetIp;
    }
}
