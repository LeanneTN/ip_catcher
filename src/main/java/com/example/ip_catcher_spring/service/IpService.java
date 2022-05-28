package com.example.ip_catcher_spring.service;

import com.example.ip_catcher_spring.domain.Receiver;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class IpService {

    public List<String> packageGetter(String index, boolean mode, String packageNum, String tempTime){
        List<String> arguments = new ArrayList<>();
        NetworkInterface[] devices = JpcapCaptor.getDeviceList();

        int indexInt = Integer.parseInt(index);
        try{
            JpcapCaptor jpcap = JpcapCaptor.openDevice(devices[indexInt], 2000, mode, Integer.parseInt(tempTime));
            //使用arp（地址解析协议）
            jpcap.setFilter("arp", true);
            jpcap.processPacket(Integer.parseInt(packageNum), new Receiver());
            int i = 0;
            while (i < Integer.parseInt(packageNum)) {
                Packet packet = jpcap.getPacket();
                System.out.println(packet);
                i++;// 捕获四个数据包
            }
        }catch(Exception ex){
            ex.printStackTrace();
        }

        return arguments;
    }
}
