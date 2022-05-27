package com.example.ip_catcher_spring.controller;

import com.example.ip_catcher_spring.service.DeviceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;

@Controller
public class DevicesController {
    @Autowired
    private DeviceService deviceService;

    @RequestMapping("/main")
    public String init_page(HttpSession session){
        session.setAttribute("devicesList", deviceService.get_devices_list());
        return "main";
    }
}
