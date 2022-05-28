package com.example.ip_catcher_spring.controller;

import com.example.ip_catcher_spring.service.DeviceService;
import com.example.ip_catcher_spring.service.IpService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;

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
        ipService.packageGetter(device,true,packagesNum,tempTime);
        return "data";
    }
}
