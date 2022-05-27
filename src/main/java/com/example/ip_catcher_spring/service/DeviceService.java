package com.example.ip_catcher_spring.service;

import com.example.ip_catcher_spring.domain.Device;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class DeviceService {
    public List<Device> get_devices_list(){
        List<Device> deviceList = new ArrayList<>();

        NetworkInterface[] devices = JpcapCaptor.getDeviceList();
        int k = -1;

        for(NetworkInterface n: devices){
            k++;
            Device device = new Device();
            device.setDeviceName(n.name);
            device.setDeviceIndex(k);
            device.setDeviceDescn(n.description);
            deviceList.add(device);
        }

        return deviceList;
    }
}
