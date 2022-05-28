package com.example.ip_catcher_spring.controller;

import com.example.ip_catcher_spring.domain.IpPacket;
import com.example.ip_catcher_spring.service.DeviceService;
import com.example.ip_catcher_spring.service.IpService;
import jpcap.packet.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;

@Controller
public class DevicesController {
    private boolean mode = true;

    @Autowired
    private DeviceService deviceService;

    @Autowired
    private IpService ipService;

    @RequestMapping("/main")
    public String init_page(HttpSession session){
        session.setAttribute("devicesList", deviceService.get_devices_list());
        return "main";
    }

    @RequestMapping("/info_update")
    public String data_select(HttpSession session,
                              String device,
                              String selected,
                              String packagesNum,
                              String tempTime){

        String msg, keyWord;
        if(selected.equals("mix")){
            keyWord="";
        }else if(selected.equals("ipv4")){
            keyWord="ipv4";
        }else if(selected.equals("ipv6")){
            keyWord="ipv6";
        }else if(selected.equals("tcp")){
            keyWord="tcp";
        }else if(selected.equals("udp")){
            keyWord="udp";
        }else if(selected.equals("ipv4_tcp")){
            keyWord="ip and tcp";
            mode=false;
        }else if(selected.equals("ipv6_tcp")){
            keyWord="ip and tcp";
            mode=false;
        }else if(selected.equals("ipv4_udp")){
            keyWord="ip and udp";
            mode=false;
        }else{
            keyWord="ip and udp";
            mode=false;
        }

        System.out.println(device+" "+selected+" "+packagesNum+" "+tempTime);
        List<IpPacket> packets = ipService.packageGetter(device,mode,packagesNum,tempTime,keyWord);
        if (packets.size()==0){
            msg = "Didn't get ip packages, please revise the condition";
        }else{
            msg = "Packages caught successfully, following results:";
//            for (Packet packet : packets) {
//                IpPacket temp = new IpPacket();
//                if (packet.getClass().equals(IPPacket.class)) {
//                    temp.IpSetter(packet);
//                    temp.commonSetter(packet);
//                } else if (packet.getClass().equals(TCPPacket.class)) {
//                    temp.commonSetter(packet);
//                    temp.tcpSetter(packet);
//                } else if (packet.getClass().equals(UDPPacket.class)) {
//                    temp.commonSetter(packet);
//                    temp.udpSetter(packet);
//                } else if (packet.getClass().equals(ICMPPacket.class)) {
//                    temp.commonSetter(packet);
//                    temp.icmpSetter(packet);
//                } else if (packet.getClass().equals(ARPPacket.class)) {
//                    temp.commonSetter(packet);
//                    temp.arpSetter(packet);
//                } else {
//                    System.out.println("其他类型协议");
//                }
//                packages.add(temp);
//            }
        }
        session.setAttribute("msg", msg);
        session.setAttribute("packets", packets);
        return "data";
    }
}
