package com.example.ip_catcher_spring.service;

import com.example.ip_catcher_spring.domain.Receiver;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class IpService {

    public List<Packet> packageGetter(String index, boolean mode, String packageNum, String tempTime){
        List<Packet> arguments = new ArrayList<>();
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();

        int indexInt = Integer.parseInt(index);
        JpcapCaptor jpcap = null;
        try{
            jpcap = JpcapCaptor.openDevice(devices[indexInt], 2000, mode, Integer.parseInt(tempTime));
            //使用arp（地址解析协议）
            jpcap.setFilter("arp", true);
            jpcap.processPacket(Integer.parseInt(packageNum), new Receiver());
        }catch(Exception ex){
            ex.printStackTrace();
        }
        int i = 0;
        List<String> packageInfo = new ArrayList<>();
        while (i < Integer.parseInt(packageNum)) {
            Packet packet = jpcap.getPacket();
            arguments.add(packet);;
            i++;// 捕获四个数据包
        }
        return arguments;
    }
}
