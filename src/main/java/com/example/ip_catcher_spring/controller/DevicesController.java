package com.example.ip_catcher_spring.controller;

import com.example.ip_catcher_spring.domain.IpPacket;
import com.example.ip_catcher_spring.service.DeviceService;
import com.example.ip_catcher_spring.service.IpService;
import jpcap.packet.Packet;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.List;

@Controller
public class DevicesController {
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

        System.out.println(device+" "+selected+" "+packagesNum+" "+tempTime);
        List<Packet> packets = ipService.packageGetter(device,true,packagesNum,tempTime);
        List<IpPacket> packages = new ArrayList<>();
        String msg;
        if (packets.size()==0){
            msg = "Didn't get ip packages, please revise the condition";
        }else{
            msg = "Packages caught successfully, following results:";
            for(int i = 0; i < packets.size(); i++){

            }
        }
        session.setAttribute("msg", msg);
        session.setAttribute("packets", packets);
        return "data";
    }
}
